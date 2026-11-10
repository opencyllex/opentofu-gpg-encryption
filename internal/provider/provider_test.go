package provider_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"opentofu-gpg-key-provider/internal/provider"
)

type output struct {
	Keys struct {
		EncryptionKey []byte `json:"encryption_key"`
		DecryptionKey []byte `json:"decryption_key"`
	} `json:"keys"`
	Meta json.RawMessage `json:"meta"`
}

func TestHeaderBeforeInput(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	t.Cleanup(func() {
		inputReader.Close()
		inputWriter.Close()
		outputReader.Close()
		outputWriter.Close()
	})
	done := make(chan error, 1)
	go func() {
		done <- provider.Run(t.Context(), inputReader, outputWriter, newWrapper(t))
		outputWriter.Close()
	}()
	header := make(chan string, 1)
	reader := bufio.NewReader(outputReader)
	go func() {
		line, _ := reader.ReadString('\n')
		header <- line
	}()
	select {
	case line := <-header:
		checkHeader(t, line)
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not send its header before input")
	}
	if _, err := io.WriteString(inputWriter, "null"); err != nil {
		t.Fatal(err)
	}
	inputWriter.Close()
	var result output
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(result.Keys.EncryptionKey) != 32 {
		t.Fatalf("encryption key length = %d, want 32", len(result.Keys.EncryptionKey))
	}
}

func TestKeyRecoveryAndRotation(t *testing.T) {
	wrapper := newWrapper(t)
	first := request(t, wrapper, "null")
	if len(first.Keys.DecryptionKey) != 0 {
		t.Fatal("initial response included a decryption key")
	}
	second := request(t, wrapper, string(first.Meta))
	if !bytes.Equal(second.Keys.DecryptionKey, first.Keys.EncryptionKey) {
		t.Fatal("stored metadata did not recover the original encryption key")
	}
	if bytes.Equal(second.Keys.EncryptionKey, first.Keys.EncryptionKey) {
		t.Fatal("provider reused its encryption key")
	}
	third := request(t, wrapper, string(second.Meta))
	if !bytes.Equal(third.Keys.DecryptionKey, second.Keys.EncryptionKey) {
		t.Fatal("new metadata does not describe the new encryption key")
	}

	// Exercise the actual AES-GCM contract using the public protocol keys.
	block, err := aes.NewCipher(first.Keys.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, encryptor.NonceSize())
	ciphertext := encryptor.Seal(nil, nonce, []byte("state payload"), nil)
	block, err = aes.NewCipher(second.Keys.DecryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptor.Open(nil, nonce, ciphertext, nil)
	if err != nil || string(plaintext) != "state payload" {
		t.Fatalf("AES-GCM recovery failed: %q, %v", plaintext, err)
	}
}

func TestInvalidMetadata(t *testing.T) {
	for _, input := range []string{
		"", "{", "[]", "null null", "{}", `{"external_data":null}`,
		`{"external_data":{"version":2,"encrypted_key":"AQ=="}}`,
		`{"external_data":{"version":1}}`,
		`{"external_data":{"version":1,"encrypted_key":"invalid base64"}}`,
		`{"external_data":{"version":1,"encrypted_key":"AQ=="}}`,
	} {
		t.Run(input, func(t *testing.T) {
			var stdout bytes.Buffer
			err := provider.Run(t.Context(), strings.NewReader(input), &stdout, newWrapper(t))
			if err == nil {
				t.Fatal("invalid metadata was accepted")
			}
			if strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("failed request emitted a key response: %s", &stdout)
			}
		})
	}
}

func TestWrongKeyLength(t *testing.T) {
	wrapper := newWrapper(t)
	wrapped, err := wrapper.Encrypt(t.Context(), []byte("too short"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"external_data": map[string]any{
		"version": 1, "encrypted_key": wrapped,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := provider.Run(t.Context(), bytes.NewReader(input), &stdout, wrapper); err == nil {
		t.Fatal("provider accepted a decryption key with the wrong length")
	}
}

func TestMetadataSizeLimit(t *testing.T) {
	var stdout bytes.Buffer
	err := provider.Run(t.Context(), strings.NewReader(strings.Repeat(" ", 1024*1024+1)), &stdout, newWrapper(t))
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func request(t *testing.T, wrapper provider.KeyWrapper, input string) output {
	t.Helper()
	var stdout bytes.Buffer
	if err := provider.Run(t.Context(), strings.NewReader(input), &stdout, wrapper); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&stdout)
	header, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	checkHeader(t, header)
	var result output
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("unexpected trailing protocol data: %v", err)
	}
	return result
}

func checkHeader(t *testing.T, line string) {
	t.Helper()
	var header struct {
		Magic   string `json:"magic"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal([]byte(line), &header); err != nil {
		t.Fatal(err)
	}
	if header.Magic != "OpenTofu-External-Key-Provider" || header.Version != 1 {
		t.Fatalf("invalid header: %s", line)
	}
}

// Use an authenticated wrapper to test the protocol independently of GPG.
type memoryWrapper struct{ aead cipher.AEAD }

func newWrapper(t *testing.T) memoryWrapper {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	return memoryWrapper{aead: aead}
}

func (w memoryWrapper) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return w.aead.Seal(nil, nil, plaintext, nil), nil
}

func (w memoryWrapper) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < w.aead.Overhead() {
		return nil, errors.New("invalid wrapped key")
	}
	return w.aead.Open(nil, nil, ciphertext, nil)
}

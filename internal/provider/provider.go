package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	keyLength       = 32
	metadataVersion = 1
	maxInputSize    = 1024 * 1024
)

// KeyWrapper protects and recovers data encryption keys.
type KeyWrapper interface {
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

type metadata struct {
	ExternalData *encryptedKey `json:"external_data"`
}

type encryptedKey struct {
	Version      int    `json:"version"`
	EncryptedKey []byte `json:"encrypted_key"`
}

type keys struct {
	EncryptionKey []byte `json:"encryption_key"`
	DecryptionKey []byte `json:"decryption_key,omitempty"`
}

type response struct {
	Keys keys     `json:"keys"`
	Meta metadata `json:"meta"`
}

// Run implements version 1 of OpenTofu's external key provider protocol.
// The header is written before reading any input. Only protocol JSON is written
// to stdout; callers are responsible for reporting returned errors on stderr.
// On cancellation, callers must close stdin to release any pending read, or exit
// the process.
func Run(ctx context.Context, stdin io.Reader, stdout io.Writer, wrapper KeyWrapper) error {
	if _, err := io.WriteString(stdout, "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n"); err != nil {
		return fmt.Errorf("write protocol header: %w", err)
	}
	input, err := readInput(ctx, stdin)
	if err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}
	if len(input) > maxInputSize {
		return errors.New("input metadata exceeds the 1 MiB limit")
	}
	var previous *metadata
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&previous); err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			err = errors.New("unexpected trailing JSON data")
		}
		return fmt.Errorf("parse metadata: %w", err)
	}

	var decryptionKey []byte
	if previous != nil {
		if previous.ExternalData == nil {
			return errors.New("input metadata is missing external_data")
		}
		if previous.ExternalData.Version != metadataVersion {
			return fmt.Errorf("unsupported metadata version %d", previous.ExternalData.Version)
		}
		if len(previous.ExternalData.EncryptedKey) == 0 {
			return errors.New("input metadata is missing encrypted_key")
		}
		decryptionKey, err = wrapper.Decrypt(ctx, previous.ExternalData.EncryptedKey)
		if err != nil {
			return fmt.Errorf("recover decryption key: %w", err)
		}
		defer clear(decryptionKey)
		if len(decryptionKey) != keyLength {
			return fmt.Errorf("decrypted key must be %d bytes, got %d", keyLength, len(decryptionKey))
		}
	}

	encryptionKey := make([]byte, keyLength)
	defer clear(encryptionKey)
	rand.Read(encryptionKey)
	wrappedKey, err := wrapper.Encrypt(ctx, encryptionKey)
	if err != nil {
		return fmt.Errorf("protect encryption key: %w", err)
	}
	result := response{
		Keys: keys{EncryptionKey: encryptionKey, DecryptionKey: decryptionKey},
		Meta: metadata{ExternalData: &encryptedKey{Version: metadataVersion, EncryptedKey: wrappedKey}},
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return fmt.Errorf("write key response: %w", err)
	}
	return nil
}

func (m *metadata) UnmarshalJSON(input []byte) error {
	return decodeMetadataObject(input, map[string]any{
		"external_data": &m.ExternalData,
	})
}

func (k *encryptedKey) UnmarshalJSON(input []byte) error {
	var ciphertext string
	if err := decodeMetadataObject(input, map[string]any{
		"version":       &k.Version,
		"encrypted_key": &ciphertext,
	}); err != nil {
		return err
	}
	var err error
	k.EncryptedKey, err = base64.StdEncoding.DecodeString(ciphertext)
	return err
}

// Decode field names explicitly because encoding/json otherwise accepts case
// variants and duplicate fields, even with DisallowUnknownFields enabled.
func decodeMetadataObject(input []byte, fields map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("metadata must be a JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name := token.(string)
		target, ok := fields[name]
		if !ok {
			return fmt.Errorf("unknown metadata field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate metadata field %q", name)
		}
		seen[name] = true
		if err := decoder.Decode(target); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func readInput(ctx context.Context, stdin io.Reader) ([]byte, error) {
	type result struct {
		input []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		input, err := io.ReadAll(io.LimitReader(stdin, maxInputSize+1))
		done <- result{input: input, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.input, result.err
	}
}

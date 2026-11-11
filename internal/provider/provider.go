package provider

import (
	"context"
	"crypto/rand"
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
	if err := json.Unmarshal(input, &previous); err != nil {
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

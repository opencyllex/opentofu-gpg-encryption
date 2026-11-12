package method

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/gpg"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/policy"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/protocol"
)

type request struct {
	Payload *string
	Key     *string
}

type response struct {
	Payload []byte `json:"payload"`
}

// Run implements version 1 of OpenTofu's external encryption-method protocol.
// The optional key contains public policy from the current policy provider.
func Run(ctx context.Context, stdin io.Reader, stdout io.Writer, operation string, config policy.Config) error {
	if _, err := io.WriteString(stdout, "{\"magic\":\"OpenTofu-External-Encryption-Method\",\"version\":1}\n"); err != nil {
		return fmt.Errorf("write protocol header: %w", err)
	}
	input, err := protocol.Read(ctx, stdin, 512*1024*1024)
	if err != nil {
		return fmt.Errorf("read method request: %w", err)
	}
	defer clear(input)
	var data request
	if err := protocol.Decode(input, &data); err != nil {
		return fmt.Errorf("parse method request: %w", err)
	}
	if data.Payload == nil {
		return errors.New("method request is missing payload")
	}
	payload, err := base64.StdEncoding.DecodeString(*data.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	defer clear(payload)
	if operation == "encrypt" && len(payload) > gpg.MaxPayloadSize {
		return errors.New("payload exceeds the 256 MiB limit")
	}
	if data.Key != nil {
		encoded, err := base64.StdEncoding.DecodeString(*data.Key)
		if err != nil {
			return fmt.Errorf("decode policy: %w", err)
		}
		if len(encoded) > 1024*1024 {
			return errors.New("GPG policy exceeds the 1 MiB limit")
		}
		config, err = policy.Decode(encoded)
		if err != nil {
			return fmt.Errorf("parse GPG policy: %w", err)
		}
	}
	client := gpg.Client{Executable: config.GPG, HomeDir: config.HomeDir, AuthorizedKeys: config.AuthorizedKeys}
	var output []byte
	if operation == "encrypt" {
		output, err = client.Encrypt(ctx, payload)
	} else {
		output, err = client.Decrypt(ctx, payload)
	}
	if err != nil {
		return err
	}
	defer clear(output)
	if err := json.NewEncoder(stdout).Encode(response{Payload: output}); err != nil {
		return fmt.Errorf("write method response: %w", err)
	}
	return nil
}

func (r *request) UnmarshalJSON(input []byte) error {
	return protocol.Object(input, map[string]any{"payload": &r.Payload, "key": &r.Key})
}

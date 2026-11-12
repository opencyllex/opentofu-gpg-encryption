package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/policy"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/protocol"
)

type metadata struct {
	ExternalData *marker `json:"external_data"`
}

type marker struct {
	PolicyVersion int `json:"policy_version"`
}

type keys struct {
	EncryptionKey []byte `json:"encryption_key"`
	DecryptionKey []byte `json:"decryption_key,omitempty"`
}

type response struct {
	Keys keys     `json:"keys"`
	Meta metadata `json:"meta"`
}

// Run transports current public policy through OpenTofu's key-provider protocol.
// It performs no GPG operations and never takes authorization from metadata.
func Run(ctx context.Context, stdin io.Reader, stdout io.Writer, config policy.Config) error {
	if _, err := io.WriteString(stdout, "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n"); err != nil {
		return fmt.Errorf("write protocol header: %w", err)
	}
	input, err := protocol.Read(ctx, stdin, 1024*1024)
	if err != nil {
		return fmt.Errorf("read policy metadata: %w", err)
	}
	var previous *metadata
	if err := protocol.Decode(input, &previous); err != nil {
		return fmt.Errorf("parse policy metadata: %w", err)
	}
	if previous != nil {
		if previous.ExternalData == nil {
			return errors.New("policy metadata is missing external_data")
		}
		if previous.ExternalData.PolicyVersion != policy.Version {
			return fmt.Errorf("unsupported policy metadata version %d", previous.ExternalData.PolicyVersion)
		}
	}
	data := config.Encode()
	result := response{
		Keys: keys{EncryptionKey: data},
		Meta: metadata{ExternalData: &marker{PolicyVersion: policy.Version}},
	}
	if previous != nil {
		result.Keys.DecryptionKey = data
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return fmt.Errorf("write policy response: %w", err)
	}
	return nil
}

func (m *metadata) UnmarshalJSON(input []byte) error {
	return protocol.Object(input, map[string]any{"external_data": &m.ExternalData})
}

func (m *marker) UnmarshalJSON(input []byte) error {
	return protocol.Object(input, map[string]any{"policy_version": &m.PolicyVersion})
}

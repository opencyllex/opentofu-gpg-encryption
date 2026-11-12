package policy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/protocol"
)

const Version = 1

// Config is public authorization and GPG configuration, not encryption key
// material. It is supplied by the current trusted OpenTofu configuration.
type Config struct {
	Version        int      `json:"version"`
	AuthorizedKeys []string `json:"authorized_keys"`
	GPG            string   `json:"gpg"`
	HomeDir        string   `json:"homedir"`
}

func (c Config) Encode() []byte {
	if c.AuthorizedKeys == nil {
		c.AuthorizedKeys = []string{}
	}
	// All fields have JSON-supported types; marshaling cannot fail.
	data, _ := json.Marshal(c)
	return data
}

func Decode(data []byte) (Config, error) {
	var config Config
	if err := protocol.Decode(data, &config); err != nil {
		return config, err
	}
	if config.Version != Version {
		return config, fmt.Errorf("unsupported GPG policy version %d", config.Version)
	}
	if strings.TrimSpace(config.GPG) == "" {
		return config, errors.New("GPG policy must name a GnuPG executable")
	}
	for i, value := range config.AuthorizedKeys {
		fingerprint, err := Fingerprint(value)
		if err != nil {
			return config, err
		}
		config.AuthorizedKeys[i] = fingerprint
	}
	return config, nil
}

func (c *Config) UnmarshalJSON(input []byte) error {
	var version *int
	var authorized *[]string
	var executable, home *string
	if err := protocol.Object(input, map[string]any{
		"version":         &version,
		"authorized_keys": &authorized,
		"gpg":             &executable,
		"homedir":         &home,
	}); err != nil {
		return err
	}
	if version == nil || authorized == nil || executable == nil || home == nil {
		return errors.New("GPG policy must contain version, authorized_keys, gpg, and homedir")
	}
	*c = Config{Version: *version, AuthorizedKeys: *authorized, GPG: *executable, HomeDir: *home}
	return nil
}

func Fingerprint(value string) (string, error) {
	if len(value) != 40 && len(value) != 64 {
		return "", errors.New("authorized key must be a full GPG primary-key fingerprint (40 or 64 hexadecimal characters)")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("authorized key fingerprint must contain only hexadecimal characters")
	}
	return strings.ToUpper(value), nil
}

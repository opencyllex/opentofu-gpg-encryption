package policy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/opencyllex/opentofu-gpg-encryption/internal/protocol"
)

const Version = 2

// Config is public authorization and GPG configuration, not encryption key
// material. It is supplied by the current trusted OpenTofu configuration.
type Config struct {
	Version        int      `json:"version"`
	AuthorizedKeys []string `json:"authorized_keys"`
	RetiredKeys    []string `json:"retired_keys"`
	GPG            string   `json:"gpg"`
	HomeDir        string   `json:"homedir"`
}

// Encode emits the current policy format with both authorization lists.
func (c Config) Encode() []byte {
	c.Version = Version
	if c.AuthorizedKeys == nil {
		c.AuthorizedKeys = []string{}
	}
	if c.RetiredKeys == nil {
		c.RetiredKeys = []string{}
	}
	// All fields have JSON-supported types; marshaling cannot fail.
	data, _ := json.Marshal(c)
	return data
}

// Validate normalizes public fingerprints and keeps active and retired keys
// disjoint at the CLI and policy-input boundaries.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.GPG) == "" {
		return errors.New("GPG policy must name a GnuPG executable")
	}
	for _, fingerprints := range [][]string{c.AuthorizedKeys, c.RetiredKeys} {
		for i, value := range fingerprints {
			fingerprint, err := normalizeFingerprint(value)
			if err != nil {
				return err
			}
			fingerprints[i] = fingerprint
		}
	}
	for _, fingerprint := range c.RetiredKeys {
		if slices.Contains(c.AuthorizedKeys, fingerprint) {
			return fmt.Errorf("GPG key %s cannot be both an authorized key and a retired key", fingerprint)
		}
	}
	return nil
}

func (c *Config) UnmarshalJSON(input []byte) error {
	var version *int
	var authorized, retired *[]string
	var executable, home *string
	if err := protocol.Object(input, map[string]any{
		"version":         &version,
		"authorized_keys": &authorized,
		"retired_keys":    &retired,
		"gpg":             &executable,
		"homedir":         &home,
	}); err != nil {
		return err
	}
	if version == nil || authorized == nil || retired == nil || executable == nil || home == nil {
		return errors.New("GPG policy must contain version, authorized_keys, retired_keys, gpg, and homedir")
	}
	if *version != Version {
		return fmt.Errorf("unsupported GPG policy version %d", *version)
	}
	*c = Config{Version: *version, AuthorizedKeys: *authorized, RetiredKeys: *retired, GPG: *executable, HomeDir: *home}
	return c.Validate()
}

func normalizeFingerprint(value string) (string, error) {
	if len(value) != 40 && len(value) != 64 {
		return "", fmt.Errorf("key %q must be a full GPG primary-key fingerprint (40 or 64 hexadecimal characters)", value)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("key fingerprint %q must contain only hexadecimal characters", value)
	}
	return strings.ToUpper(value), nil
}

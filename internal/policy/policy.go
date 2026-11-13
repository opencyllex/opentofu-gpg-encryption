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
	Version             int      `json:"version"`
	AuthorizedKeys      []string `json:"authorized_keys"`
	AllowRevokedSigners []string `json:"allow_revoked_signers"`
	GPG                 string   `json:"gpg"`
	HomeDir             string   `json:"homedir"`
}

// Encode emits the current policy format, including when upgrading a v1 policy.
func (c Config) Encode() []byte {
	c.Version = Version
	if c.AuthorizedKeys == nil {
		c.AuthorizedKeys = []string{}
	}
	if c.AllowRevokedSigners == nil {
		c.AllowRevokedSigners = []string{}
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
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

// Validate normalizes public fingerprints and keeps write and recovery roles
// disjoint at the CLI and policy-input boundaries.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.GPG) == "" {
		return errors.New("GPG policy must name a GnuPG executable")
	}
	for _, fingerprints := range [][]string{c.AuthorizedKeys, c.AllowRevokedSigners} {
		for i, value := range fingerprints {
			fingerprint, err := Fingerprint(value)
			if err != nil {
				return err
			}
			fingerprints[i] = fingerprint
		}
	}
	for _, fingerprint := range c.AllowRevokedSigners {
		if slices.Contains(c.AuthorizedKeys, fingerprint) {
			return fmt.Errorf("GPG key %s cannot be both an authorized key and an allowed revoked signer", fingerprint)
		}
	}
	return nil
}

func (c *Config) UnmarshalJSON(input []byte) error {
	var version *int
	var authorized *[]string
	var revoked json.RawMessage
	var executable, home *string
	if err := protocol.Object(input, map[string]any{
		"version":               &version,
		"authorized_keys":       &authorized,
		"allow_revoked_signers": &revoked,
		"gpg":                   &executable,
		"homedir":               &home,
	}); err != nil {
		return err
	}
	if version == nil || authorized == nil || executable == nil || home == nil {
		return errors.New("GPG policy must contain version, authorized_keys, gpg, and homedir")
	}
	var allowed *[]string
	switch *version {
	case 1:
		if revoked != nil {
			return errors.New("GPG policy version 1 does not support allow_revoked_signers")
		}
	case Version:
		if revoked == nil {
			return errors.New("GPG policy version 2 must contain allow_revoked_signers")
		}
		if err := protocol.Decode(revoked, &allowed); err != nil {
			return err
		}
		if allowed == nil {
			return errors.New("GPG policy allow_revoked_signers must be an array")
		}
	default:
		return fmt.Errorf("unsupported GPG policy version %d", *version)
	}
	*c = Config{Version: *version, AuthorizedKeys: *authorized, GPG: *executable, HomeDir: *home}
	if allowed != nil {
		c.AllowRevokedSigners = *allowed
	}
	return nil
}

func Fingerprint(value string) (string, error) {
	if len(value) != 40 && len(value) != 64 {
		return "", errors.New("key must be a full GPG primary-key fingerprint (40 or 64 hexadecimal characters)")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("key fingerprint must contain only hexadecimal characters")
	}
	return strings.ToUpper(value), nil
}

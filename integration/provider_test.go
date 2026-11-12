//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const keyPurpose = "OpenTofu-GPG-Key-Provider:data-key:v1\x00"

type keyResponse struct {
	Keys struct {
		EncryptionKey []byte `json:"encryption_key"`
		DecryptionKey []byte `json:"decryption_key"`
	} `json:"keys"`
	Meta struct {
		ExternalData struct {
			Version      int    `json:"version"`
			EncryptedKey []byte `json:"encrypted_key"`
		} `json:"external_data"`
	} `json:"meta"`
}

type harness struct {
	binary  string
	gpg     string
	gpgconf string // Test cleanup only; the provider invokes only gpg.
	tofu    string
}

func TestIntegration(t *testing.T) {
	// Project-level encryption and CLI overrides from the developer's shell
	// must not redirect isolated test runs to their normal state or keyring.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "TF_ENCRYPTION" || key == "TF_DATA_DIR" || key == "TF_WORKSPACE" || strings.HasPrefix(key, "TF_CLI_ARGS") {
			t.Setenv(key, "")
		}
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Fatal("integration tests require GnuPG on PATH: ", err)
	}
	gpgconf, err := exec.LookPath(filepath.Join(filepath.Dir(gpg), "gpgconf"+filepath.Ext(gpg)))
	if err != nil {
		t.Fatal("integration tests require gpgconf alongside gpg for temporary-agent cleanup: ", err)
	}
	tofu, err := exec.LookPath("tofu")
	if err != nil {
		t.Fatal("integration tests require OpenTofu on PATH: ", err)
	}
	binary := filepath.Join(t.TempDir(), "provider with spaces"+filepath.Ext(gpg))
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/opentofu-gpg-key-provider")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, output)
	}
	h := harness{binary: binary, gpg: gpg, gpgconf: gpgconf, tofu: tofu}
	master := h.home(t)
	first := h.generateKey(t, master, "First Authorized Key <first@example.invalid>")
	second := h.generateKey(t, master, "Second Authorized Key <second@example.invalid>")
	firstHome, secondHome, publicHome := h.home(t), h.home(t), h.home(t)
	h.gpgCommand(t, firstHome, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
	h.gpgCommand(t, secondHome, h.gpgCommand(t, master, nil, "--export-secret-keys", second), "--import")
	h.gpgCommand(t, publicHome, h.gpgCommand(t, master, nil, "--export", first, second), "--import")
	for _, home := range []string{firstHome, secondHome} {
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export", first, second), "--import")
	}

	t.Run("single user without authorized-key flags", func(t *testing.T) {
		initial := h.request(t, firstHome, "null")
		recovered := h.request(t, firstHome, metadataJSON(t, initial))
		if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("single-user mode did not recover the original key")
		}
		if bytes.Equal(recovered.Keys.EncryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("single-user mode reused the encryption key")
		}
	})

	t.Run("automatic signer preserves configured keyrings", func(t *testing.T) {
		home := h.home(t)
		configure(t, home, "no-default-keyring\nkeyring signing-keys.kbx")
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
		initial := h.request(t, home, "null")
		recovered := h.request(t, home, metadataJSON(t, initial))
		if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("automatic signer selection lost the configured keyring")
		}
	})

	t.Run("first secret key and recovery", func(t *testing.T) {
		configure(t, master, "default-recipient "+second)
		initial := h.request(t, master, "null")
		if initial.Keys.DecryptionKey != nil {
			t.Fatal("initial response included a decryption key")
		}
		if initial.Meta.ExternalData.Version != 1 || len(initial.Keys.EncryptionKey) != 32 {
			t.Fatal("invalid key response")
		}
		if bytes.Contains(initial.Meta.ExternalData.EncryptedKey, initial.Keys.EncryptionKey) {
			t.Fatal("metadata contains the unwrapped encryption key")
		}
		recovered := h.request(t, master, metadataJSON(t, initial))
		if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("GPG did not recover the original key")
		}
		if bytes.Equal(recovered.Keys.EncryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("encryption key was reused")
		}
		direct := h.gpgCommand(t, firstHome, initial.Meta.ExternalData.EncryptedKey, "--decrypt")
		if !bytes.Equal(direct, dataKeyMessage(initial.Keys.EncryptionKey)) {
			t.Fatal("metadata is not interoperable with direct GPG decryption")
		}
	})

	t.Run("default signing key overrides default recipient", func(t *testing.T) {
		configure(t, master, "default-key "+second+"\ndefault-recipient "+first)
		result := h.request(t, master, "null")
		if got := h.gpgCommand(t, secondHome, result.Meta.ExternalData.EncryptedKey, "--decrypt"); !bytes.Equal(got, dataKeyMessage(result.Keys.EncryptionKey)) {
			t.Fatal("default-key did not select the authorized key")
		}
		h.request(t, secondHome, metadataJSON(t, result))
	})

	t.Run("explicit authorized key ignores default recipient", func(t *testing.T) {
		configure(t, master, "default-key "+first+"\ndefault-recipient "+second+"\ndefault-recipient-self")
		result := h.request(t, master, "null", "--authorized-key", strings.ToLower(first))
		if got := h.gpgCommand(t, firstHome, result.Meta.ExternalData.EncryptedKey, "--decrypt"); !bytes.Equal(got, dataKeyMessage(result.Keys.EncryptionKey)) {
			t.Fatal("explicit authorized key was not used for encryption")
		}
		_, stderr, err := h.exchange(t, secondHome, metadataJSON(t, result), "--authorized-key", first, "--authorized-key", second)
		if err == nil || !strings.Contains(stderr, "GPG decryption failed") {
			t.Fatalf("default recipient could decrypt an explicitly addressed key: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("multiple authorized keys can read and write", func(t *testing.T) {
		result := h.request(t, master, "null", "--authorized-key", first, "--authorized-key", second)
		for _, home := range []string{firstHome, secondHome} {
			recovered := h.request(t, home, metadataJSON(t, result), "--authorized-key", first, "--authorized-key", second)
			if !bytes.Equal(recovered.Keys.DecryptionKey, result.Keys.EncryptionKey) {
				t.Fatal("an authorized key could not recover the wrapped key")
			}
			if rewritten := h.request(t, master, metadataJSON(t, recovered), "--authorized-key", first, "--authorized-key", second); !bytes.Equal(rewritten.Keys.DecryptionKey, recovered.Keys.EncryptionKey) {
				t.Fatal("an authorized key's signature was rejected")
			}
		}
	})

	t.Run("configured encrypt-to cannot add readers", func(t *testing.T) {
		configure(t, firstHome, "encrypt-to "+second)
		t.Cleanup(func() { configure(t, firstHome, "") })
		result := h.request(t, firstHome, "null", "--authorized-key", first)
		_, stderr, err := h.exchange(t, secondHome, metadataJSON(t, result), "--authorized-key", first, "--authorized-key", second)
		if err == nil || !strings.Contains(stderr, "GPG decryption failed") {
			t.Fatalf("encrypt-to added an unauthorized reader: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("local-user selects an authorized signer", func(t *testing.T) {
		configure(t, master, "default-key "+first+"\nlocal-user "+second)
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		result := h.request(t, master, "null", "--authorized-key", first, "--authorized-key", second)
		h.request(t, secondHome, metadataJSON(t, result))
	})

	t.Run("sole authorized signer overrides default-key", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		for _, flags := range [][]string{
			{"--authorized-key", second},
			{"--authorized-key", second, "--authorized-key", second},
		} {
			initial := h.request(t, master, "null", flags...)
			recovered := h.request(t, secondHome, metadataJSON(t, initial))
			if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
				t.Fatal("the sole authorized key was not selected for signing")
			}
		}
	})

	t.Run("configured local-users must all be authorized", func(t *testing.T) {
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		for _, options := range []string{"local-user " + first, "local-user " + first + "\nlocal-user " + second} {
			configure(t, master, options)
			stdout, stderr, err := h.exchange(t, master, "null", "--authorized-key", second)
			if err == nil || !strings.Contains(stderr, "signing key "+first+" is not authorized") || !strings.Contains(stderr, "every configured local-user must be authorized") || bytes.Contains(stdout, []byte("encryption_key")) {
				t.Fatalf("unauthorized local-user was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
			}
		}
	})

	t.Run("multiple local-users with explicit and implicit authorization", func(t *testing.T) {
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		for _, test := range []struct {
			name string
			args []string
		}{
			{"explicit", []string{"--authorized-key", first, "--authorized-key", second}},
			{"implicit", nil},
		} {
			t.Run(test.name, func(t *testing.T) {
				configure(t, master, "local-user "+first+"\nlocal-user "+second)
				initial := h.request(t, master, "null", test.args...)
				for _, home := range []string{firstHome, secondHome} {
					recovered := h.request(t, home, metadataJSON(t, initial), "--authorized-key", first, "--authorized-key", second)
					if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
						t.Fatal("an authorized key could not recover a multiply signed key")
					}
				}
				for _, test := range []struct {
					home       string
					authorized string
					omitted    string
				}{
					{firstHome, first, second},
					{secondHome, second, first},
				} {
					stdout, stderr, err := h.exchange(t, test.home, metadataJSON(t, initial), "--authorized-key", test.authorized)
					if err == nil || !strings.Contains(stderr, "recover decryption key: GPG signature from key "+test.omitted+" is not authorized") || bytes.Contains(stdout, []byte("decryption_key")) {
						t.Fatalf("an unauthorized co-signature was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
					}
				}
				configure(t, master, "local-user "+second)
				transition := h.request(t, master, metadataJSON(t, initial), "--authorized-key", first, "--authorized-key", second)
				rotated := h.request(t, secondHome, metadataJSON(t, transition))
				if !bytes.Equal(transition.Keys.DecryptionKey, initial.Keys.EncryptionKey) || !bytes.Equal(rotated.Keys.DecryptionKey, transition.Keys.EncryptionKey) {
					t.Fatal("a retired co-signer could not be removed after rewriting its signature")
				}
			})
		}
	})

	t.Run("ambiguous authorized signers use default-key", func(t *testing.T) {
		configure(t, master, "default-key "+second)
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		initial := h.request(t, master, "null", "--authorized-key", first, "--authorized-key", second)
		h.request(t, secondHome, metadataJSON(t, initial))
	})

	t.Run("ambiguous signers reject an unauthorized default-key", func(t *testing.T) {
		home := h.home(t)
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first, second), "--import")
		other := h.generateKey(t, home, "Unrelated Default <other@example.invalid>")
		configure(t, home, "default-key "+other)
		stdout, stderr, err := h.exchange(t, home, "null", "--authorized-key", first, "--authorized-key", second)
		if err == nil || !strings.Contains(stderr, "signing key "+other+" is not authorized") || bytes.Contains(stdout, []byte("encryption_key")) {
			t.Fatalf("an unauthorized default-key was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
		}
	})

	t.Run("reject forged wrapped keys", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		attackerHome := h.home(t)
		// Matching user IDs do not make an attacker's signature authorized.
		attacker := h.generateKey(t, attackerHome, "First Authorized Key <first@example.invalid>")
		h.gpgCommand(t, attackerHome, h.gpgCommand(t, master, nil, "--export", first), "--import")
		h.gpgCommand(t, master, h.gpgCommand(t, attackerHome, nil, "--export", attacker), "--import")
		key := bytes.Repeat([]byte{42}, 32)
		message := dataKeyMessage(key)
		signed := h.gpgCommand(t, master, message, "--compress-algo", "none", "--local-user", first, "--sign")
		changed := bytes.Clone(signed)
		keyOffset := bytes.Index(changed, key)
		if keyOffset < 0 {
			t.Fatal("signed test packet does not contain the uncompressed key")
		}
		changed[keyOffset] ^= 1
		emptySignature := h.gpgCommand(t, master, nil, "--compress-algo", "none", "--local-user", first, "--sign")
		literal := h.gpgCommand(t, master, message, "--compress-algo", "none", "--store")
		for _, test := range []struct {
			name       string
			ciphertext []byte
		}{
			{"unsigned public-key-only wrapping", h.gpgCommand(t, publicHome, message, "--recipient", first, "--encrypt")},
			{"unauthorized signer", h.gpgCommand(t, master, message, "--local-user", second, "--recipient", first, "--sign", "--encrypt")},
			{"matching email", h.gpgCommand(t, attackerHome, message, "--local-user", attacker, "--recipient", first, "--sign", "--encrypt")},
			{"bad signature inside intact encryption", h.gpgCommand(t, publicHome, changed, "--no-literal", "--recipient", first, "--encrypt")},
			{"unrelated signature and unsigned key", h.gpgCommand(t, publicHome, append(emptySignature, literal...), "--no-literal", "--recipient", first, "--encrypt")},
			{"text signature", h.gpgCommand(t, master, message, "--textmode", "--local-user", first, "--recipient", first, "--sign", "--encrypt")},
		} {
			t.Run(test.name, func(t *testing.T) {
				var result keyResponse
				result.Meta.ExternalData.Version = 1
				result.Meta.ExternalData.EncryptedKey = test.ciphertext
				stdout, stderr, err := h.exchange(t, master, metadataJSON(t, result))
				if err == nil || !strings.Contains(stderr, "recover decryption key") || bytes.Contains(stdout, []byte("encryption_key")) || bytes.Contains(stdout, []byte("decryption_key")) {
					t.Fatalf("forged wrapped key was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
				}
			})
		}
	})

	t.Run("reject signatures made for another purpose", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		for _, message := range [][]byte{
			bytes.Repeat([]byte{42}, 32),
			append([]byte("Another-Protocol:data-key:v1\x00"), bytes.Repeat([]byte{42}, 32)...),
		} {
			var result keyResponse
			result.Meta.ExternalData.Version = 1
			result.Meta.ExternalData.EncryptedKey = h.gpgCommand(t, master, message, "--recipient", first, "--sign", "--encrypt")
			stdout, stderr, err := h.exchange(t, master, metadataJSON(t, result))
			if err == nil || !strings.Contains(stderr, "not tagged as an OpenTofu data key") || bytes.Contains(stdout, []byte("decryption_key")) {
				t.Fatalf("unrelated signature was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
			}
		}
	})

	t.Run("skip-verify cannot bypass signature checks", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		result := h.request(t, master, "null")
		configure(t, master, "default-key "+first+"\nskip-verify")
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		stdout, stderr, err := h.exchange(t, master, metadataJSON(t, result))
		if err == nil || !strings.Contains(stderr, "signatures from authorized keys") || bytes.Contains(stdout, []byte("decryption_key")) {
			t.Fatalf("skip-verify bypassed signature checks: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
		}
	})

	t.Run("signing and encryption subkeys", func(t *testing.T) {
		home := h.home(t)
		fingerprint := h.generateKey(t, home, "Subkey Test <subkeys@example.invalid>")
		for _, usage := range []string{"sign", "encr"} {
			h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", usage, "1d")
		}
		initial := h.request(t, home, "null", "--authorized-key", fingerprint)
		recovered := h.request(t, home, metadataJSON(t, initial))
		if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("the primary fingerprint did not authorize the signing subkey")
		}
		subkeyHome := h.home(t)
		h.gpgCommand(t, subkeyHome, h.gpgCommand(t, home, nil, "--export-secret-subkeys", fingerprint), "--import")
		initial = h.request(t, subkeyHome, "null")
		recovered = h.request(t, subkeyHome, metadataJSON(t, initial))
		if !bytes.Equal(recovered.Keys.DecryptionKey, initial.Keys.EncryptionKey) {
			t.Fatal("signer discovery required the primary secret key instead of the signing subkey")
		}
	})

	t.Run("reject expired and revoked signatures", func(t *testing.T) {
		for _, name := range []string{"expired signature", "revoked signing subkey"} {
			t.Run(name, func(t *testing.T) {
				home := h.home(t)
				created := time.Now().Add(-time.Hour)
				fingerprint := h.generateKey(t, home, "Signature Validity <validity@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
				args := []string{"--recipient", fingerprint, "--sign", "--encrypt"}
				if name == "expired signature" {
					args = append([]string{"--faked-system-time", strconv.FormatInt(created.Add(time.Minute).Unix(), 10), "--default-sig-expire", "seconds=60"}, args...)
				} else {
					h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
				}
				var result keyResponse
				result.Meta.ExternalData.Version = 1
				result.Meta.ExternalData.EncryptedKey = h.gpgCommand(t, home, dataKeyMessage(bytes.Repeat([]byte{42}, 32)), args...)
				if name == "revoked signing subkey" {
					h.gpgCommand(t, home, []byte("key 1\nrevkey\ny\n0\n\ny\nsave\n"), "--command-fd", "0", "--pinentry-mode", "loopback", "--passphrase", "", "--edit-key", fingerprint)
				}
				stdout, stderr, err := h.exchange(t, home, metadataJSON(t, result))
				if err == nil || !strings.Contains(stderr, "recover decryption key") || bytes.Contains(stdout, []byte("encryption_key")) || bytes.Contains(stdout, []byte("decryption_key")) {
					t.Fatalf("invalid signature was accepted: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
				}
			})
		}
	})

	t.Run("configured output cannot redirect protocol", func(t *testing.T) {
		unexpected := filepath.ToSlash(filepath.Join(t.TempDir(), "unexpected-key-output"))
		configure(t, master, "default-key "+first+"\noutput "+unexpected)
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		h.request(t, master, "null")
		if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
			t.Fatalf("GPG wrote its configured output file: %v", err)
		}
	})

	t.Run("configured text mode preserves binary keys", func(t *testing.T) {
		configure(t, master, "default-key "+first+"\ntextmode")
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		// Exercise a byte that text mode would change on this platform.
		// Keys without such bytes could round-trip correctly by chance.
		for range 512 {
			initial := h.request(t, master, "null")
			key := initial.Keys.EncryptionKey
			if runtime.GOOS == "windows" {
				newline := bytes.IndexByte(key, '\n')
				if newline < 0 || (newline > 0 && key[newline-1] == '\r') {
					continue
				}
			} else if bytes.IndexByte(key, '\r') < 0 {
				continue
			}
			recovered := h.request(t, master, metadataJSON(t, initial))
			if !bytes.Equal(recovered.Keys.DecryptionKey, key) {
				t.Fatal("GPG's textmode setting changed the binary data key")
			}
			return
		}
		t.Fatal("could not generate a data key containing a text-sensitive byte")
	})

	t.Run("GNUPGHOME", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, h.binary, "--gpg", h.gpg)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+master)
		cmd.Stdin = strings.NewReader("null")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.Output()
		if err != nil {
			t.Fatalf("GNUPGHOME request: %v\n%s", err, &stderr)
		}
		decodeResponse(t, stdout)
	})

	t.Run("missing secret signing key", func(t *testing.T) {
		for _, home := range []string{h.home(t), publicHome} {
			for _, args := range [][]string{nil, {"--authorized-key", first}} {
				stdout, stderr, err := h.exchange(t, home, "null", args...)
				if err == nil || !strings.Contains(stderr, "GPG signing failed") || bytes.Contains(stdout, []byte("encryption_key")) {
					t.Fatalf("missing secret signing key: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
				}
			}
		}
	})

	t.Run("invalid explicit authorized keys", func(t *testing.T) {
		home := h.home(t)
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export", second), "--import")
		configure(t, home, "trust-model pgp")
		h.gpgCommand(t, home, []byte(first+":6:\n"), "--import-ownertrust")
		for _, test := range []struct {
			name        string
			fingerprint string
		}{
			{"unknown", strings.Repeat("0", 40)},
			{"untrusted", second},
		} {
			t.Run(test.name, func(t *testing.T) {
				stdout, stderr, err := h.exchange(t, home, "null", "--authorized-key", first, "--authorized-key", test.fingerprint)
				if err == nil || !strings.Contains(stderr, "GPG encryption failed") || bytes.Contains(stdout, []byte("encryption_key")) {
					t.Fatalf("invalid authorized key: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
				}
			})
		}
	})

	t.Run("invalid ciphertext and missing secret key", func(t *testing.T) {
		valid := h.request(t, master, "null", "--authorized-key", first)
		for _, home := range []string{secondHome, publicHome} {
			if _, _, err := h.exchange(t, home, metadataJSON(t, valid), "--authorized-key", first, "--authorized-key", second); err == nil {
				t.Fatal("recovery succeeded without the authorized key's private key")
			}
		}
		valid.Meta.ExternalData.EncryptedKey[len(valid.Meta.ExternalData.EncryptedKey)-1] ^= 1
		stdout, _, err := h.exchange(t, master, metadataJSON(t, valid), "--authorized-key", first)
		if err == nil || bytes.Contains(stdout, []byte("decryption_key")) {
			t.Fatal("tampered ciphertext returned key material")
		}
	})

	t.Run("GPG settings cannot bypass integrity checks or leak session keys", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		key := bytes.Repeat([]byte{42}, 32)
		ciphertext := h.gpgCommand(t, master, dataKeyMessage(key), "--rfc4880", "--recipient", first, "--sign", "--encrypt")
		var result keyResponse
		result.Meta.ExternalData.Version = 1
		result.Meta.ExternalData.EncryptedKey = ciphertext
		configure(t, master, "default-key "+first+"\nignore-mdc-error\nshow-session-key")
		t.Cleanup(func() { configure(t, master, "default-key "+first) })
		if recovered := h.request(t, master, metadataJSON(t, result)); !bytes.Equal(recovered.Keys.DecryptionKey, key) {
			t.Fatal("GPG settings prevented recovery of an intact MDC-protected key")
		}
		ciphertext[len(ciphertext)-1] ^= 1
		for _, options := range []string{"ignore-mdc-error", "show-session-key", "ignore-mdc-error\nshow-session-key"} {
			t.Run(options, func(t *testing.T) {
				configure(t, master, "default-key "+first+"\n"+options)
				stdout, stderr, err := h.exchange(t, master, metadataJSON(t, result))
				if err == nil || bytes.Contains(stdout, []byte("encryption_key")) || bytes.Contains(stdout, []byte("decryption_key")) {
					t.Fatal("GPG's ignore-mdc-error setting bypassed integrity verification")
				}
				if strings.Contains(stderr, "SESSION_KEY") || strings.Contains(stderr, "session key") {
					t.Fatalf("GPG diagnostics exposed a session key: %s", stderr)
				}
				if options == "show-session-key" && !strings.Contains(stderr, "gpg:") {
					t.Fatalf("show-session-key suppressed useful GPG error messages: %s", stderr)
				}
			})
		}
	})

	t.Run("reject unencrypted literal packet", func(t *testing.T) {
		literal := h.gpgCommand(t, master, bytes.Repeat([]byte{42}, 32), "--store")
		var result keyResponse
		result.Meta.ExternalData.Version = 1
		result.Meta.ExternalData.EncryptedKey = literal
		_, stderr, err := h.exchange(t, master, metadataJSON(t, result), "--authorized-key", first)
		if err == nil || !strings.Contains(stderr, "public-key decryption") {
			t.Fatalf("unencrypted literal packet: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("reject wrong key lengths", func(t *testing.T) {
		for _, test := range []struct {
			size       int
			diagnostic string
		}{
			{16, "must be 32 bytes"},
			{33, "--max-output"},
			{4096, "--max-output"},
		} {
			var result keyResponse
			result.Meta.ExternalData.Version = 1
			result.Meta.ExternalData.EncryptedKey = h.gpgCommand(t, master, dataKeyMessage(make([]byte, test.size)), "--recipient", first, "--sign", "--encrypt")
			_, stderr, err := h.exchange(t, master, metadataJSON(t, result), "--authorized-key", first)
			if err == nil || !strings.Contains(stderr, test.diagnostic) {
				t.Fatalf("%d-byte key: err=%v, stderr=%q; want %q", test.size, err, stderr, test.diagnostic)
			}
		}
	})

	t.Run("timeout", func(t *testing.T) {
		_, stderr, err := h.exchange(t, master, "null", "--authorized-key", first, "--timeout", "1ns")
		if err == nil || !strings.Contains(stderr, "deadline exceeded") {
			t.Fatalf("timeout: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("OpenTofu state plans and rotation", func(t *testing.T) {
		configure(t, firstHome, "default-key "+first)
		configure(t, secondHome, "default-key "+second)
		configure(t, master, "default-key "+first)
		project := t.TempDir()
		h.writeProject(t, project, master)
		h.tofuCommand(t, project, "init", "-input=false", "-no-color")
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		assertEncrypted(t, filepath.Join(project, "terraform.tfstate"))
		if value := h.tofuCommand(t, project, "output", "-raw", "secret"); value != "integration-secret-sentinel" {
			t.Fatalf("decrypted state output = %q", value)
		}
		h.tofuCommand(t, project, "plan", "-input=false", "-no-color", "-out=saved.tfplan")
		assertEncrypted(t, filepath.Join(project, "saved.tfplan"))
		if plan := h.tofuCommand(t, project, "show", "-json", "saved.tfplan"); !strings.Contains(plan, "integration-secret-sentinel") {
			t.Fatal("OpenTofu could not decrypt the saved plan")
		}
		for _, test := range []struct {
			name string
			file string
			args []string
		}{
			{"forged state", "terraform.tfstate", []string{"output", "-raw", "-no-color", "secret"}},
			{"forged saved plan", "saved.tfplan", []string{"apply", "-input=false", "-no-color", "saved.tfplan"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				path := filepath.Join(project, test.file)
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				forged := h.forgeEnvelope(t, original, master, publicHome, first)
				if err := os.WriteFile(path, forged, 0600); err != nil {
					t.Fatal(err)
				}
				output, commandErr := h.runTofu(t, project, test.args...)
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				if commandErr == nil || !strings.Contains(output, "signatures from authorized keys") {
					t.Fatalf("OpenTofu accepted a forged envelope with enforced=true: err=%v\n%s", commandErr, output)
				}
			})
		}
		h.tofuCommand(t, project, "apply", "-input=false", "-no-color", "saved.tfplan")

		// Authorize the old signer during the transition. The new key signs
		// the rewrite before the old authorization and reader are removed.
		h.writeProject(t, project, master, first, second)
		configure(t, master, "default-key "+second)
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		h.writeProject(t, project, secondHome)
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		if value := h.tofuCommand(t, project, "output", "-raw", "secret"); value != "integration-secret-sentinel" {
			t.Fatal("rotated state could not be read with the new private key alone")
		}
		h.writeProject(t, project, firstHome)
		output, err := h.runTofu(t, project, "output", "-raw", "-no-color", "secret")
		if err == nil || !strings.Contains(output, "GPG decryption failed") {
			t.Fatalf("removed key reading rotated state: err=%v\n%s", err, output)
		}
	})
}

func (h harness) home(t *testing.T) string {
	t.Helper()
	parent := ""
	if runtime.GOOS == "darwin" {
		// macOS's default temporary path can exceed the Unix-domain socket
		// limit once GPG appends its agent socket names.
		parent = "/tmp"
	}
	home, err := os.MkdirTemp(parent, "tofu-gpg with spaces-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(home); err != nil {
			t.Errorf("remove temporary GPG home: %v", err)
		}
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, h.gpgconf, "--homedir", home, "--kill", "all")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("stop temporary GPG agents: %v\n%s", err, output)
		}
	})
	configure(t, home, "")
	return home
}

func configure(t *testing.T, home, options string) {
	t.Helper()
	// Trust only applies to disposable test keys in this isolated keyring.
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte("trust-model always\n"+options+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func (h harness) generateKey(t *testing.T, home, name string, options ...string) string {
	t.Helper()
	args := append([]string{"--pinentry-mode", "loopback", "--passphrase", ""}, options...)
	args = append(args, "--quick-generate-key", name, "rsa2048", "sign,encr", "1d")
	h.gpgCommand(t, home, nil, args...)
	listing := h.gpgCommand(t, home, nil, "--with-colons", "--list-keys", name)
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "fpr" {
			return fields[9]
		}
	}
	t.Fatal("generated key has no fingerprint")
	return ""
}

func (h harness) gpgCommand(t *testing.T, home string, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	args = append([]string{"--homedir", home, "--batch", "--no-tty", "--output", "-"}, args...)
	cmd := exec.CommandContext(ctx, h.gpg, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("GPG test setup/verification: %v\n%s", err, &stderr)
	}
	return output
}

func (h harness) exchange(t *testing.T, home, input string, args ...string) ([]byte, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	args = append([]string{"--gpg", h.gpg, "--homedir", home}, args...)
	cmd := exec.CommandContext(ctx, h.binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// OpenTofu waits for this line before providing metadata.
	reader := bufio.NewReader(stdout)
	header, err := reader.ReadString('\n')
	if err != nil {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("provider did not send a header before input: %v\n%s", err, &stderr)
	}
	if header != "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n" {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("invalid protocol header: %q", header)
	}
	if _, err := io.WriteString(stdin, input); err != nil {
		t.Error(err)
	}
	stdin.Close()
	body, readErr := io.ReadAll(reader)
	err = cmd.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return append([]byte(header), body...), stderr.String(), err
}

func (h harness) request(t *testing.T, home, input string, args ...string) keyResponse {
	t.Helper()
	stdout, stderr, err := h.exchange(t, home, input, args...)
	if err != nil {
		t.Fatalf("provider request: %v\n%s", err, stderr)
	}
	return decodeResponse(t, stdout)
}

func decodeResponse(t *testing.T, stdout []byte) keyResponse {
	t.Helper()
	_, body, found := bytes.Cut(stdout, []byte("\n"))
	if !found {
		t.Fatal("missing header")
	}
	var result keyResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("unexpected trailing protocol data: %v", err)
	}
	return result
}

func metadataJSON(t *testing.T, result keyResponse) string {
	t.Helper()
	data, err := json.Marshal(result.Meta)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func dataKeyMessage(key []byte) []byte {
	return append([]byte(keyPurpose), key...)
}

// Keep a valid state/plan payload, but replace its encryption with AES-GCM under
// an attacker's chosen key, wrapped using only the authorized public key.
func (h harness) forgeEnvelope(t *testing.T, original []byte, ownerHome, publicHome, fingerprint string) []byte {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(original, &envelope); err != nil {
		t.Fatal(err)
	}
	var metadata map[string][]byte
	if err := json.Unmarshal(envelope["meta"], &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 1 {
		t.Fatal("expected one external key provider in the encrypted envelope")
	}
	var encrypted []byte
	if err := json.Unmarshal(envelope["encrypted_data"], &encrypted); err != nil {
		t.Fatal(err)
	}
	for name, data := range metadata {
		var wrapped keyResponse
		if err := json.Unmarshal(data, &wrapped.Meta); err != nil {
			t.Fatal(err)
		}
		message := h.gpgCommand(t, ownerHome, wrapped.Meta.ExternalData.EncryptedKey, "--decrypt")
		defer clear(message)
		originalKey, ok := bytes.CutPrefix(message, []byte(keyPurpose))
		if !ok {
			t.Fatal("GPG did not recover a tagged data key")
		}
		block, err := aes.NewCipher(originalKey)
		if err != nil {
			t.Fatal(err)
		}
		decryptor, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := decryptor.Open(nil, encrypted[:decryptor.NonceSize()], encrypted[decryptor.NonceSize():], nil)
		if err != nil {
			t.Fatal(err)
		}
		chosenKey := bytes.Repeat([]byte{42}, 32)
		wrapped.Meta.ExternalData.EncryptedKey = h.gpgCommand(t, publicHome, dataKeyMessage(chosenKey), "--recipient", fingerprint, "--encrypt")
		metadata[name], err = json.Marshal(wrapped.Meta)
		if err != nil {
			t.Fatal(err)
		}
		block, err = aes.NewCipher(chosenKey)
		if err != nil {
			t.Fatal(err)
		}
		encryptor, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			t.Fatal(err)
		}
		envelope["encrypted_data"], err = json.Marshal(encryptor.Seal(nil, nil, plaintext, nil))
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	envelope["meta"], err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return forged
}

func (h harness) writeProject(t *testing.T, dir, home string, authorizedKeys ...string) {
	t.Helper()
	args := []string{h.binary, "--gpg", h.gpg, "--homedir", home}
	for _, fingerprint := range authorizedKeys {
		args = append(args, "--authorized-key", fingerprint)
	}
	command, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`terraform {
  encryption {
    key_provider "external" "gpg" {
      command = %s
    }
    method "aes_gcm" "gpg" {
      keys = key_provider.external.gpg
    }
    state {
      method   = method.aes_gcm.gpg
      enforced = true
    }
    plan {
      method   = method.aes_gcm.gpg
      enforced = true
    }
  }
}
resource "terraform_data" "example" {
  input = "integration-secret-sentinel"
}
output "secret" {
  value     = terraform_data.example.output
  sensitive = true
}
`, command)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
}

func (h harness) tofuCommand(t *testing.T, dir string, args ...string) string {
	t.Helper()
	output, err := h.runTofu(t, dir, args...)
	if err != nil {
		t.Fatalf("tofu %s (%s): %v\n%s", strings.Join(args, " "), runtime.GOOS, err, output)
	}
	return output
}

func (h harness) runTofu(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.tofu, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func assertEncrypted(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("integration-secret-sentinel")) {
		t.Fatalf("%s contains plaintext sensitive data", path)
	}
	if !bytes.Contains(data, []byte("encrypted_data")) {
		t.Fatalf("%s is missing OpenTofu's encrypted envelope", path)
	}
}

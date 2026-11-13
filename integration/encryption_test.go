//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	payloadPurpose = "OpenTofu-GPG-Encryption:payload:v1\x00"
	traceGPG       = "OPENTOFU_ENCRYPTION_TEST_GPG"
	traceLog       = "OPENTOFU_ENCRYPTION_TEST_LOG"
)

// The test executable also acts as a GPG forwarding wrapper. Its trace contains
// only operation names, never arguments, payloads, passphrases, or session keys.
func TestMain(m *testing.M) {
	if slices.Contains(os.Args[1:], "--status-fd") {
		real := os.Getenv(traceGPG)
		if real == "" {
			fmt.Fprintln(os.Stderr, "GPG test wrapper requires "+traceGPG)
			os.Exit(1)
		}
		operation := "other"
		for _, option := range []string{"--sign", "--decrypt", "--encrypt", "--list-secret-keys", "--list-keys"} {
			if slices.Contains(os.Args[1:], option) {
				operation = strings.TrimPrefix(option, "--")
				break
			}
		}
		if log := os.Getenv(traceLog); log != "" {
			file, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			_, err = fmt.Fprintln(file, operation)
			file.Close()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		cmd := exec.Command(real, os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				os.Exit(exit.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type policyResponse struct {
	Keys struct {
		EncryptionKey []byte `json:"encryption_key"`
		DecryptionKey []byte `json:"decryption_key"`
	} `json:"keys"`
	Meta json.RawMessage `json:"meta"`
}

type methodResponse struct {
	Payload []byte `json:"payload"`
}

type harness struct {
	binary  string
	gpg     string
	gpgconf string // Test-only agent cleanup.
	tofu    string
	wrapper string
}

func TestIntegration(t *testing.T) {
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "TF_ENCRYPTION" || key == "TF_DATA_DIR" || key == "TF_WORKSPACE" || strings.HasPrefix(key, "TF_CLI_ARGS") {
			t.Setenv(key, "")
		}
	}
	gpg := executable(t, "gpg")
	gpgconf := executable(t, filepath.Join(filepath.Dir(gpg), "gpgconf"+filepath.Ext(gpg)))
	tofu := executable(t, "tofu")
	wrapper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "encryption with spaces"+filepath.Ext(gpg))
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/opentofu-gpg-encryption")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build encryption executable: %v\n%s", err, output)
	}
	h := harness{binary: binary, gpg: gpg, gpgconf: gpgconf, tofu: tofu, wrapper: wrapper}
	t.Setenv(traceGPG, h.gpg)
	t.Setenv(traceLog, "")
	// Even a regression in policy handling must never fall back to the user's
	// normal keyring. Explicit --homedir options select the disposable keys.
	t.Setenv("GNUPGHOME", h.home(t))
	master := h.home(t)
	first := h.generateKey(t, master, "First Authorized Key <first@example.invalid>")
	second := h.generateKey(t, master, "Second Authorized Key <second@example.invalid>")
	firstHome, secondHome, publicHome := h.home(t), h.home(t), h.home(t)
	h.gpgCommand(t, firstHome, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
	h.gpgCommand(t, secondHome, h.gpgCommand(t, master, nil, "--export-secret-keys", second), "--import")
	public := h.gpgCommand(t, master, nil, "--export", first, second)
	for _, home := range []string{firstHome, secondHome, publicHome} {
		h.gpgCommand(t, home, public, "--import")
	}
	message := []byte("integration-secret-sentinel")
	both := []string{"--authorized-key", first, "--authorized-key", second}

	t.Run("single user without a provider or authorized-key flags", func(t *testing.T) {
		for _, plaintext := range [][]byte{message, {}} {
			ciphertext := h.method(t, "encrypt", firstHome, plaintext, nil)
			if bytes.Contains(ciphertext, message) {
				t.Fatal("ciphertext contains the plaintext")
			}
			if got := h.method(t, "decrypt", firstHome, ciphertext, nil); !bytes.Equal(got, plaintext) {
				t.Fatal("single-user payload did not round-trip")
			}
			if direct := h.gpgCommand(t, firstHome, ciphertext, "--decrypt"); !bytes.Equal(direct, tagged(plaintext)) {
				t.Fatal("the payload is not interoperable with direct GPG decryption")
			}
			if next := h.method(t, "encrypt", firstHome, plaintext, nil); bytes.Equal(next, ciphertext) {
				t.Fatal("GPG reused a complete encrypted message")
			}
		}
	})

	t.Run("GPG wrapper forwards without tracing", func(t *testing.T) {
		ciphertext := h.method(t, "encrypt", firstHome, message, nil, "--gpg", h.wrapper)
		if got := h.method(t, "decrypt", firstHome, ciphertext, nil, "--gpg", h.wrapper); !bytes.Equal(got, message) {
			t.Fatal("GPG forwarding without a trace did not round-trip")
		}
	})

	t.Run("GNUPGHOME resolves the single-user keyring", func(t *testing.T) {
		t.Setenv("GNUPGHOME", firstHome)
		stdout, stderr, err := h.exchange(t, "encrypt", methodInput(t, message, nil), "--gpg", h.gpg)
		if err != nil {
			t.Fatalf("encrypt with GNUPGHOME: %v\n%s", err, stderr)
		}
		ciphertext := decodeResponse[methodResponse](t, stdout).Payload
		stdout, stderr, err = h.exchange(t, "decrypt", methodInput(t, ciphertext, nil), "--gpg", h.gpg)
		if err != nil {
			t.Fatalf("decrypt with GNUPGHOME: %v\n%s", err, stderr)
		}
		if got := decodeResponse[methodResponse](t, stdout).Payload; !bytes.Equal(got, message) {
			t.Fatal("the keyring selected by GNUPGHOME did not round-trip")
		}
	})

	t.Run("policy is current public configuration and performs no GPG operations", func(t *testing.T) {
		log := h.startTrace(t)
		initial := h.policy(t, firstHome, "null", append(both, "--gpg", h.wrapper)...)
		if operations := traceOperations(t, log); len(operations) != 0 {
			t.Fatalf("policy provider invoked GPG: %v", operations)
		}
		ciphertext := h.method(t, "encrypt", firstHome, message, initial.Keys.EncryptionKey, "--timeout", "30s")
		current := h.policy(t, secondHome, string(initial.Meta), both...)
		if got := h.method(t, "decrypt", secondHome, ciphertext, current.Keys.DecryptionKey); !bytes.Equal(got, message) {
			t.Fatal("the shared policy was not passed to the external method")
		}
		removed := h.policy(t, secondHome, string(initial.Meta), "--authorized-key", second)
		h.reject(t, "decrypt", secondHome, ciphertext, removed.Keys.DecryptionKey, "signature from key "+first+" is not authorized")
	})

	t.Run("single-user policy without explicit authorized keys", func(t *testing.T) {
		initial := h.policy(t, firstHome, "null")
		ciphertext := h.method(t, "encrypt", firstHome, message, initial.Keys.EncryptionKey)
		current := h.policy(t, firstHome, string(initial.Meta))
		if got := h.method(t, "decrypt", firstHome, ciphertext, current.Keys.DecryptionKey); !bytes.Equal(got, message) {
			t.Fatal("single-user policy did not round-trip the payload")
		}
	})

	t.Run("retired keys do not authorize writes even before revocation", func(t *testing.T) {
		ciphertext := h.method(t, "encrypt", firstHome, message, nil)
		if got := h.method(t, "decrypt", firstHome, ciphertext, nil, "--retired-key", first); !bytes.Equal(got, message) {
			t.Fatal("retired-key authorization could not verify its signer")
		}
		log := h.startTrace(t)
		h.reject(t, "encrypt", firstHome, message, nil, "--retired-key only permits reads; list active members with --authorized-key to write", "--retired-key", first, "--gpg", h.wrapper)
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("recovery-only configuration performed a private write operation: %v", operations)
		}
	})

	t.Run("sole authorized signer overrides default-key and ignores recipient defaults", func(t *testing.T) {
		configure(t, master, "default-key "+first+"\ndefault-recipient "+first+"\ndefault-recipient-self\nencrypt-to "+first)
		ciphertext := h.method(t, "encrypt", master, message, nil, "--authorized-key", strings.ToLower(second))
		if got := h.method(t, "decrypt", secondHome, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("the sole authorized signer was not selected")
		}
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "GPG decryption failed", both...)
	})

	t.Run("multiple eligible signers use GPG configuration", func(t *testing.T) {
		for _, options := range []string{"default-key " + second, "default-key " + first + "\nlocal-user " + second} {
			configure(t, master, options)
			ciphertext := h.method(t, "encrypt", master, message, nil, both...)
			if got := h.method(t, "decrypt", secondHome, ciphertext, nil); !bytes.Equal(got, message) {
				t.Fatal("GPG's selected signer was not used")
			}
		}
	})

	t.Run("unauthorized default-key fails with multiple eligible signers", func(t *testing.T) {
		home := h.home(t)
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first, second), "--import")
		unauthorized := h.generateKey(t, home, "Unauthorized Default <default@example.invalid>")
		configure(t, home, "default-key "+unauthorized)
		h.reject(t, "encrypt", home, message, nil, "signing key "+unauthorized+" is not authorized", both...)
	})

	t.Run("configured local-users must all be authorized", func(t *testing.T) {
		configure(t, master, "local-user "+first)
		h.reject(t, "encrypt", master, message, nil, "signing key "+first+" is not authorized", "--authorized-key", second)
	})

	t.Run("multiple signatures and co-signer rotation", func(t *testing.T) {
		configure(t, master, "local-user "+first+"\nlocal-user "+second)
		log := h.startTrace(t)
		ciphertext := h.method(t, "encrypt", master, message, nil, append(both, "--gpg", h.wrapper)...)
		if operations := traceOperations(t, log); operations["sign"] != 1 || operations["encrypt"] != 1 {
			t.Fatalf("a payload write did not use one signing and one encryption command: %v", operations)
		}
		for _, home := range []string{firstHome, secondHome} {
			if got := h.method(t, "decrypt", home, ciphertext, nil, both...); !bytes.Equal(got, message) {
				t.Fatal("a multiply signed message could not be recovered")
			}
		}
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "signature from key "+second+" is not authorized")
		h.reject(t, "decrypt", secondHome, ciphertext, nil, "signature from key "+first+" is not authorized")
		configure(t, master, "local-user "+second)
		plaintext := h.method(t, "decrypt", master, ciphertext, nil, both...)
		rewritten := h.method(t, "encrypt", master, plaintext, nil, both...)
		if got := h.method(t, "decrypt", secondHome, rewritten, nil); !bytes.Equal(got, message) {
			t.Fatal("a retired co-signer could not be removed after rewriting")
		}
	})

	t.Run("ambiguous implicit authorization fails without signing a probe", func(t *testing.T) {
		ciphertext := h.method(t, "encrypt", firstHome, message, nil)
		log := h.startTrace(t)
		h.reject(t, "decrypt", master, ciphertext, nil, "multiple local GPG keys", "--gpg", h.wrapper)
		h.reject(t, "encrypt", master, message, nil, "multiple local GPG keys", "--gpg", h.wrapper)
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["decrypt"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("ambiguous authorization performed a private operation: %v", operations)
		}
	})

	t.Run("duplicate keyring entries are one local identity", func(t *testing.T) {
		home := h.home(t)
		configure(t, home, "no-default-keyring\nkeyring first.gpg")
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
		if err := os.WriteFile(filepath.Join(home, "second.gpg"), h.gpgCommand(t, master, nil, "--export", first), 0600); err != nil {
			t.Fatal(err)
		}
		configure(t, home, "no-default-keyring\nkeyring first.gpg\nkeyring second.gpg")
		ciphertext := h.method(t, "encrypt", home, message, nil)
		if got := h.method(t, "decrypt", home, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("duplicate keyring entries made single-user authorization ambiguous")
		}
	})

	t.Run("custom keyring and binary payloads preserve GPG configuration", func(t *testing.T) {
		home := h.home(t)
		unexpected := filepath.ToSlash(filepath.Join(t.TempDir(), "unexpected-output"))
		configure(t, home, "no-default-keyring\nkeyring custom.kbx\ntextmode\noutput "+unexpected)
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
		plaintext := make([]byte, 512*1024)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}
		ciphertext := h.method(t, "encrypt", home, plaintext, nil)
		if got := h.method(t, "decrypt", home, ciphertext, nil); !bytes.Equal(got, plaintext) {
			t.Fatal("GPG settings changed the binary payload")
		}
		compressed := h.gpgCommand(t, home, tagged(plaintext), "--no-textmode", "--cipher-algo", "AES256", "--compress-algo", "zlib", "--recipient", first, "--sign", "--encrypt")
		if got := h.method(t, "decrypt", home, compressed, nil); !bytes.Equal(got, plaintext) {
			t.Fatal("compressed binary payload changed while growing the output buffer")
		}
		if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
			t.Fatalf("GPG wrote its configured output file: %v", err)
		}
	})

	t.Run("signing subkeys and decryption without a signing private key", func(t *testing.T) {
		home := h.home(t)
		fingerprint := h.generateKey(t, home, "Subkeys <subkeys@example.invalid>")
		h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "encr", "1d")
		readHome := h.home(t)
		h.gpgCommand(t, readHome, h.gpgCommand(t, home, nil, "--export-secret-subkeys", fingerprint), "--import")
		ciphertext := h.method(t, "encrypt", home, message, nil)
		if got := h.method(t, "decrypt", readHome, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("recovery required a signing private key")
		}
		h.reject(t, "encrypt", readHome, message, nil, "no usable GPG signing secret key")
		h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
		ciphertext = h.method(t, "encrypt", home, message, nil, "--authorized-key", fingerprint)
		if got := h.method(t, "decrypt", home, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("a signing subkey was not authorized by its primary fingerprint")
		}
	})

	t.Run("reject public-key-only and signature forgeries", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		attackerHome := h.home(t)
		attacker := h.generateKey(t, attackerHome, "First Authorized Key <first@example.invalid>")
		h.gpgCommand(t, attackerHome, public, "--import")
		h.gpgCommand(t, firstHome, h.gpgCommand(t, attackerHome, nil, "--export", attacker), "--import")
		signed := h.gpgCommand(t, master, tagged(message), "--compress-algo", "none", "--sign")
		changed := bytes.Clone(signed)
		offset := bytes.Index(changed, message)
		if offset < 0 {
			t.Fatal("signed fixture does not contain the uncompressed payload")
		}
		changed[offset] ^= 1
		emptySigned := h.gpgCommand(t, master, tagged([]byte{}), "--compress-algo", "none", "--sign")
		unsignedTail := h.gpgCommand(t, master, message, "--compress-algo", "none", "--store")
		for _, test := range []struct {
			name string
			data []byte
		}{
			{"unsigned", h.gpgCommand(t, publicHome, tagged(message), "--recipient", first, "--encrypt")},
			{"unauthorized signer", h.gpgCommand(t, master, tagged(message), "--local-user", second, "--recipient", first, "--sign", "--encrypt")},
			{"matching email", h.gpgCommand(t, attackerHome, tagged(message), "--local-user", attacker, "--recipient", first, "--sign", "--encrypt")},
			{"bad signature", h.gpgCommand(t, publicHome, changed, "--no-literal", "--recipient", first, "--encrypt")},
			{"unsigned trailing payload", h.gpgCommand(t, publicHome, append(emptySigned, unsignedTail...), "--no-literal", "--recipient", first, "--encrypt")},
			{"text signature", h.gpgCommand(t, master, tagged(message), "--textmode", "--recipient", first, "--sign", "--encrypt")},
			{"unencrypted signed message", signed},
			{"unencrypted literal", h.gpgCommand(t, master, tagged(message), "--store")},
		} {
			t.Run(test.name, func(t *testing.T) {
				h.reject(t, "decrypt", firstHome, test.data, nil, "GPG")
				h.reject(t, "decrypt", firstHome, test.data, nil, "GPG", "--retired-key", first)
			})
		}
	})

	t.Run("purpose tags and verification settings cannot be bypassed", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		for _, plaintext := range [][]byte{message, append([]byte("Another-Protocol:v1\x00"), message...)} {
			ciphertext := h.gpgCommand(t, master, plaintext, "--recipient", first, "--sign", "--encrypt")
			h.reject(t, "decrypt", firstHome, ciphertext, nil, "not tagged as an OpenTofu payload")
			h.reject(t, "decrypt", firstHome, ciphertext, nil, "not tagged as an OpenTofu payload", "--retired-key", first)
		}
		ciphertext := h.method(t, "encrypt", firstHome, message, nil)
		configure(t, firstHome, "skip-verify")
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "valid binary signatures")
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "valid binary signatures", "--retired-key", first)
	})

	t.Run("reject expired and revoked signatures", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			expiredKey bool
		}{
			{"expired signature", false},
			{"expired signature", true},
			{"expired signature and revoked primary key", false},
			{"expired signature and revoked primary key", true},
			{"revoked primary key", false},
			{"revoked primary key", true},
			{"revoked signing subkey", false},
			{"revoked signing subkey", true},
		} {
			name := test.name
			if test.expiredKey {
				name += " with expired key"
			}
			t.Run(name, func(t *testing.T) {
				home := h.home(t)
				created := time.Now().Add(-time.Hour)
				if test.expiredKey {
					created = time.Now().Add(-48 * time.Hour)
				}
				fingerprint := h.generateKey(t, home, "Signature Validity <validity@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
				args := []string{"--faked-system-time", strconv.FormatInt(created.Add(time.Minute).Unix(), 10), "--recipient", fingerprint, "--sign", "--encrypt"}
				expiredSignature := strings.HasPrefix(test.name, "expired signature")
				if expiredSignature {
					args = append([]string{"--default-sig-expire", "seconds=60"}, args...)
				} else if test.name == "revoked signing subkey" {
					h.gpgCommand(t, home, nil, "--faked-system-time", strconv.FormatInt(created.Unix(), 10), "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
				}
				ciphertext := h.gpgCommand(t, home, tagged(message), args...)
				if test.name != "expired signature" {
					commands := "revkey\ny\n0\n\ny\nsave\n"
					if test.name == "revoked signing subkey" {
						commands = "key 1\n" + commands
					}
					h.gpgCommand(t, home, []byte(commands), "--command-fd", "0", "--pinentry-mode", "loopback", "--passphrase", "", "--edit-key", fingerprint)
				}
				diagnostic := "GPG"
				if !expiredSignature {
					diagnostic = "GPG signing key " + fingerprint + " has been revoked"
				}
				stderr := h.reject(t, "decrypt", home, ciphertext, nil, diagnostic, "--authorized-key", fingerprint)
				if test.name == "revoked signing subkey" && !strings.Contains(stderr, "(signing subkey ") {
					t.Fatal("revoked subkey diagnostic did not include the subkey as extra detail")
				}
				if expiredSignature {
					h.reject(t, "decrypt", home, ciphertext, nil, "GPG", "--retired-key", fingerprint)
					return
				}
				options := []string{"--retired-key", strings.ToLower(fingerprint)}
				if got := h.method(t, "decrypt", home, ciphertext, nil, options...); !bytes.Equal(got, message) {
					t.Fatal("explicit recovery authorization did not accept the revoked signer")
				}
				policy := h.policy(t, home, "null", options...)
				if got := h.method(t, "decrypt", home, ciphertext, policy.Keys.DecryptionKey); !bytes.Equal(got, message) {
					t.Fatal("the policy provider did not transport revoked-signer recovery authorization")
				}
				h.reject(t, "encrypt", home, message, policy.Keys.EncryptionKey, "--retired-key only permits reads")
				changed := bytes.Clone(ciphertext)
				changed[len(changed)-1] ^= 1
				h.reject(t, "decrypt", home, changed, policy.Keys.DecryptionKey, "GPG")
			})
		}
	})

	t.Run("revocation recovery verifies every co-signer", func(t *testing.T) {
		home := h.home(t)
		retired := h.generateKey(t, home, "Retired Co-signer <retired@example.invalid>")
		other := h.generateKey(t, home, "Other Retired Co-signer <other-retired@example.invalid>")
		current := h.generateKey(t, home, "Active Co-signer <active@example.invalid>")
		configure(t, home, "local-user "+retired+"\nlocal-user "+other+"\nlocal-user "+current)
		ciphertext := h.method(t, "encrypt", home, message, nil, "--authorized-key", retired, "--authorized-key", other, "--authorized-key", current)
		for _, fingerprint := range []string{retired, other} {
			h.gpgCommand(t, home, []byte("revkey\ny\n0\n\ny\nsave\n"), "--command-fd", "0", "--pinentry-mode", "loopback", "--passphrase", "", "--edit-key", fingerprint)
		}
		options := []string{"--authorized-key", current, "--retired-key", retired}
		h.reject(t, "decrypt", home, ciphertext, nil, "has been revoked", append(slices.Clone(options), "--authorized-key", other)...)
		h.reject(t, "decrypt", home, ciphertext, nil, "signature from key "+other+" is not authorized", options...)
		options = append(options, "--retired-key", other)
		if got := h.method(t, "decrypt", home, ciphertext, nil, options...); !bytes.Equal(got, message) {
			t.Fatal("explicitly allowing every revoked co-signer did not recover the payload")
		}
		configure(t, home, "")
		rewritten := h.method(t, "encrypt", home, message, nil, options...)
		if got := h.method(t, "decrypt", home, rewritten, nil, "--authorized-key", current); !bytes.Equal(got, message) {
			t.Fatal("a recovery-only signer was used to sign the rewritten payload")
		}
	})

	t.Run("GPG signature expiry settings do not expire state", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-3 * time.Hour)
		h.generateKey(t, home, "Nonexpiring Signature <expiry@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
		configure(t, home, "ask-sig-expire\ndefault-sig-expire seconds=60\nfaked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		ciphertext := h.method(t, "encrypt", home, message, nil)
		configure(t, home, "")
		if got := h.method(t, "decrypt", home, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("the state signature inherited GPG's default expiry")
		}
	})

	t.Run("expired keys allow historical reads but cannot write", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fingerprint := h.generateKey(t, home, "Expired Key <expired@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
		configure(t, home, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		ciphertext := h.method(t, "encrypt", home, message, nil)
		configure(t, home, "")
		for _, options := range [][]string{nil, {"--authorized-key", fingerprint}} {
			h.reject(t, "encrypt", home, message, nil, "key "+fingerprint+" has expired", options...)
			if got := h.method(t, "decrypt", home, ciphertext, nil, options...); !bytes.Equal(got, message) {
				t.Fatal("key expiry prevented reading historical state")
			}
			policy := h.policy(t, home, "null", options...)
			h.reject(t, "encrypt", home, message, policy.Keys.EncryptionKey, "key "+fingerprint+" has expired")
			if got := h.method(t, "decrypt", home, ciphertext, policy.Keys.DecryptionKey); !bytes.Equal(got, message) {
				t.Fatal("key expiry prevented reading historical state with a policy provider")
			}
		}
		h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-set-expire", fingerprint, "2y")
		rewritten := h.method(t, "encrypt", home, message, nil)
		if got := h.method(t, "decrypt", home, rewritten, nil); !bytes.Equal(got, message) {
			t.Fatal("renewing the key did not restore writes")
		}
	})

	t.Run("expired signing subkeys allow historical reads but cannot write", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fakeTime := strconv.FormatInt(created.Unix(), 10)
		fingerprint := h.generateKeyWithUsage(t, home, "Expired Signing Subkey <subkey-expiry@example.invalid>", "cert", "2y", "--faked-system-time", fakeTime)
		h.gpgCommand(t, home, nil, "--faked-system-time", fakeTime, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "encr", "2y")
		h.gpgCommand(t, home, nil, "--faked-system-time", fakeTime, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
		configure(t, home, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		ciphertext := h.method(t, "encrypt", home, message, nil)
		configure(t, home, "")
		if status := h.decryptionStatus(t, home, ciphertext); !bytes.Contains(status, []byte("[GNUPG:] EXPKEYSIG ")) {
			t.Fatal("the historical fixture was not signed by an expired subkey")
		}
		log := h.startTrace(t)
		for _, options := range [][]string{nil, {"--authorized-key", fingerprint}} {
			if got := h.method(t, "decrypt", home, ciphertext, nil, options...); !bytes.Equal(got, message) {
				t.Fatal("signing subkey expiry prevented reading historical state")
			}
			h.reject(t, "encrypt", home, message, nil, "GPG signing key "+fingerprint+" has expired", append(slices.Clone(options), "--gpg", h.wrapper)...)
		}
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("expired signing subkey performed a private write operation: %v", operations)
		}
	})

	t.Run("expired recipients fail before signing and can be retired", func(t *testing.T) {
		for _, subkey := range []bool{false, true} {
			name := "primary key"
			if subkey {
				name = "encryption subkey"
			}
			t.Run(name, func(t *testing.T) {
				retiredHome, currentHome := h.home(t), h.home(t)
				created := time.Now().Add(-48 * time.Hour)
				fakeTime := strconv.FormatInt(created.Unix(), 10)
				var retired string
				if subkey {
					retired = h.generateKeyWithUsage(t, retiredHome, "Expired Recipient Subkey <recipient-subkey@example.invalid>", "sign", "2y", "--faked-system-time", fakeTime)
					h.gpgCommand(t, retiredHome, nil, "--faked-system-time", fakeTime, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", retired, "rsa2048", "encr", "1d")
				} else {
					retired = h.generateKey(t, retiredHome, "Expired Recipient <recipient@example.invalid>", "--faked-system-time", fakeTime)
				}
				current := h.generateKeyWithUsage(t, currentHome, "Current Writer <current-writer@example.invalid>", "sign,encr", "2y", "--faked-system-time", fakeTime)
				h.gpgCommand(t, retiredHome, h.gpgCommand(t, currentHome, nil, "--export", current), "--import")
				h.gpgCommand(t, currentHome, h.gpgCommand(t, retiredHome, nil, "--export", retired), "--import")
				authorized := []string{"--authorized-key", retired, "--authorized-key", current}
				configure(t, retiredHome, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
				ciphertext := h.method(t, "encrypt", retiredHome, message, nil, authorized...)
				configure(t, retiredHome, "")
				if got := h.method(t, "decrypt", currentHome, ciphertext, nil, authorized...); !bytes.Equal(got, message) {
					t.Fatal("recipient expiry prevented reading historical state")
				}

				log := h.startTrace(t)
				for _, home := range []string{retiredHome, currentHome} {
					options := append(slices.Clone(authorized), "--gpg", h.wrapper)
					stderr := h.reject(t, "encrypt", home, message, nil, "key "+retired+" has expired", options...)
					if !strings.Contains(stderr, "--retired-key") {
						t.Fatal("expiry diagnostic did not explain retirement")
					}
					policy := h.policy(t, home, "null", options...)
					h.reject(t, "encrypt", home, message, policy.Keys.EncryptionKey, "key "+retired+" has expired")
				}
				if operations := traceOperations(t, log); operations["sign"] != 0 || operations["encrypt"] != 0 {
					t.Fatalf("expired recipient was detected after a private write operation: %v", operations)
				}

				options := []string{"--authorized-key", current, "--retired-key", retired}
				policy := h.policy(t, currentHome, "null", options...)
				for _, key := range [][]byte{nil, policy.Keys.DecryptionKey} {
					var flags []string
					if key == nil {
						flags = options
					}
					plaintext := h.method(t, "decrypt", currentHome, ciphertext, key, flags...)
					if !bytes.Equal(plaintext, message) {
						t.Fatal("retired, unrevoked key could not authenticate historical state")
					}
					rewritten := h.method(t, "encrypt", currentHome, plaintext, key, flags...)
					if got := h.method(t, "decrypt", currentHome, rewritten, nil, "--authorized-key", current); !bytes.Equal(got, message) {
						t.Fatal("retiring an expired key did not restore writes with the current signer")
					}
					h.reject(t, "decrypt", retiredHome, rewritten, nil, "GPG decryption failed", "--authorized-key", current)
				}
				h.reject(t, "decrypt", currentHome, ciphertext, nil, "signature from key "+retired+" is not authorized", "--authorized-key", current)
			})
		}
	})

	t.Run("an expired encryption subkey does not block a usable replacement", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fakeTime := strconv.FormatInt(created.Unix(), 10)
		fingerprint := h.generateKeyWithUsage(t, home, "Renewed Recipient <renewed-recipient@example.invalid>", "sign", "2y", "--faked-system-time", fakeTime)
		for _, expiry := range []string{"1d", "2y"} {
			h.gpgCommand(t, home, nil, "--faked-system-time", fakeTime, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fingerprint, "rsa2048", "encr", expiry)
		}
		ciphertext := h.method(t, "encrypt", home, message, nil)
		if got := h.method(t, "decrypt", home, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("an unusable old encryption subkey prevented use of its replacement")
		}
	})

	t.Run("expired co-signers must remain authorized", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fakeTime := strconv.FormatInt(created.Unix(), 10)
		expired := h.generateKey(t, home, "Expired Co-signer <expired-cosigner@example.invalid>", "--faked-system-time", fakeTime)
		current := h.generateKey(t, home, "Current Co-signer <current-cosigner@example.invalid>", "--faked-system-time", fakeTime)
		h.gpgCommand(t, home, nil, "--faked-system-time", fakeTime, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-set-expire", current, "2y")
		configure(t, home, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10)+"\nlocal-user "+expired+"\nlocal-user "+current)
		authorized := []string{"--authorized-key", expired, "--authorized-key", current}
		ciphertext := h.method(t, "encrypt", home, message, nil, authorized...)
		configure(t, home, "")
		readHome := h.home(t)
		h.gpgCommand(t, readHome, h.gpgCommand(t, home, nil, "--export-secret-keys", current), "--import")
		h.gpgCommand(t, readHome, h.gpgCommand(t, home, nil, "--export", expired), "--import")
		if got := h.method(t, "decrypt", readHome, ciphertext, nil, authorized...); !bytes.Equal(got, message) {
			t.Fatal("an expired authorized co-signer prevented reading historical state")
		}
		for _, options := range [][]string{nil, {"--authorized-key", current}} {
			h.reject(t, "decrypt", readHome, ciphertext, nil, "signature from key "+expired+" is not authorized", options...)
		}
	})

	t.Run("expired identities still require explicit authorization with multiple local keys", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		expired := h.generateKey(t, home, "Expired Identity <expired-identity@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
		configure(t, home, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		ciphertext := h.method(t, "encrypt", home, message, nil)
		configure(t, home, "")
		current := h.generateKey(t, home, "Current Identity <current-identity@example.invalid>")
		log := h.startTrace(t)
		h.reject(t, "decrypt", home, ciphertext, nil, "multiple local GPG keys", "--gpg", h.wrapper)
		h.reject(t, "encrypt", home, message, nil, "multiple local GPG keys", "--gpg", h.wrapper)
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["decrypt"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("ambiguous authorization performed a private operation: %v", operations)
		}
		if got := h.method(t, "decrypt", home, ciphertext, nil, "--authorized-key", expired); !bytes.Equal(got, message) {
			t.Fatal("explicit authorization did not recover historical state")
		}
		h.method(t, "encrypt", home, message, nil, "--authorized-key", current)
	})

	t.Run("integrity failures cannot leak session keys", func(t *testing.T) {
		configure(t, master, "default-key "+first)
		ciphertext := h.gpgCommand(t, master, tagged(message), "--rfc4880", "--recipient", first, "--sign", "--encrypt")
		configure(t, firstHome, "ignore-mdc-error\nshow-session-key")
		if got := h.method(t, "decrypt", firstHome, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("intact MDC-protected data could not be recovered")
		}
		ciphertext[len(ciphertext)-1] ^= 1
		stderr := h.reject(t, "decrypt", firstHome, ciphertext, nil, "GPG")
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "GPG", "--retired-key", first)
		if strings.Contains(stderr, "SESSION_KEY") || strings.Contains(stderr, "session key") {
			t.Fatalf("diagnostics exposed a session key: %s", stderr)
		}
	})

	t.Run("public keys alone cannot write or read", func(t *testing.T) {
		h.reject(t, "encrypt", publicHome, message, nil, "no authorized GPG key has a usable signing secret key", both...)
		ciphertext := h.method(t, "encrypt", firstHome, message, nil)
		h.reject(t, "decrypt", publicHome, ciphertext, nil, "GPG decryption failed", both...)
	})

	t.Run("untrusted recipient diagnostics omit the no-literal note", func(t *testing.T) {
		home := h.home(t)
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
		h.gpgCommand(t, home, public, "--import")
		configure(t, home, "trust-model pgp")
		h.gpgCommand(t, home, []byte(first+":6:\n"), "--import-ownertrust")
		stderr := h.reject(t, "encrypt", home, message, nil, "GPG encryption failed", both...)
		if strings.Contains(stderr, "--no-literal") {
			t.Fatalf("encryption diagnostics included the no-literal note: %s", stderr)
		}
	})

	t.Run("AEAD integrity and AES-256 encryption", func(t *testing.T) {
		options := h.gpgCommand(t, firstHome, nil, "--dump-options")
		if !slices.Contains(strings.Fields(string(options)), "--force-aead") {
			t.Skip("installed GPG does not support force-aead")
		}
		configure(t, firstHome, "force-aead")
		ciphertext := h.method(t, "encrypt", firstHome, message, nil)
		status := h.decryptionStatus(t, firstHome, ciphertext)
		var aead bool
		for line := range strings.SplitSeq(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[0] == "[GNUPG:]" && fields[1] == "DECRYPTION_INFO" && fields[2] == "0" && fields[3] == "9" && fields[4] != "0" {
				aead = true
			}
		}
		if !aead {
			t.Fatal("GPG did not confirm AEAD with AES-256")
		}
		if got := h.method(t, "decrypt", firstHome, ciphertext, nil); !bytes.Equal(got, message) {
			t.Fatal("AEAD-protected data could not be recovered")
		}
		ciphertext[len(ciphertext)-1] ^= 1
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "GPG")
	})

	t.Run("reject other payload ciphers", func(t *testing.T) {
		ciphertext := h.gpgCommand(t, firstHome, tagged(message), "--cipher-algo", "AES128", "--recipient", first, "--sign", "--encrypt")
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "did not confirm AES-256")
	})

	t.Run("decompressed plaintext is bounded by max-output", func(t *testing.T) {
		// Keep the oversized fixture on pipes: compress a stream of zeros rather
		// than allocating another full plaintext in the test process.
		plaintext := io.MultiReader(strings.NewReader(payloadPurpose), io.LimitReader(zeroReader{}, 256*1024*1024+1))
		ciphertext := h.gpgStreamCommand(t, firstHome, plaintext, "--cipher-algo", "AES256", "--compress-algo", "zlib", "--recipient", first, "--sign", "--encrypt")
		h.reject(t, "decrypt", firstHome, ciphertext, nil, "max-output")
	})

	t.Run("timeout", func(t *testing.T) {
		h.reject(t, "encrypt", firstHome, message, nil, "deadline exceeded", "--timeout", "1ns")
	})

	t.Run("OpenTofu reads historical state and saved plans after key expiry", func(t *testing.T) {
		home := h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fingerprint := h.generateKey(t, home, "Historical State <historical@example.invalid>", "--faked-system-time", strconv.FormatInt(created.Unix(), 10))
		configure(t, home, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		project := t.TempDir()
		h.writeProject(t, project, home, false)
		h.tofuCommand(t, project, "init", "-input=false", "-no-color")
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		h.tofuCommand(t, project, "plan", "-input=false", "-no-color", "-out=saved.tfplan")
		assertEncrypted(t, filepath.Join(project, "terraform.tfstate"))
		assertEncrypted(t, filepath.Join(project, "saved.tfplan"))
		configure(t, home, "")
		log := h.startTrace(t)
		if output := h.tofuCommand(t, project, "output", "-raw", "secret"); output != string(message) {
			t.Fatal("key expiry prevented OpenTofu from reading historical state")
		}
		if output := h.tofuCommand(t, project, "show", "-json", "saved.tfplan"); !strings.Contains(output, string(message)) {
			t.Fatal("key expiry prevented OpenTofu from reading a historical saved plan")
		}
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("historical reads performed signing or encryption: %v", operations)
		}
		if output, err := h.runTofu(t, project, "plan", "-input=false", "-no-color", "-out=expired.tfplan"); err == nil || !strings.Contains(strings.Join(strings.Fields(output), " "), "key "+fingerprint+" has expired") {
			t.Fatalf("OpenTofu wrote a new plan with an expired key: err=%v\n%s", err, output)
		}
	})

	for _, usePolicy := range []bool{false, true} {
		name := "method only"
		if usePolicy {
			name = "shared policy"
		}
		t.Run("OpenTofu "+name, func(t *testing.T) {
			configure(t, firstHome, "")
			project := t.TempDir()
			var authorized []string
			if usePolicy {
				authorized = []string{first, second}
			}
			h.writeProject(t, project, firstHome, usePolicy, authorized...)
			log := h.startTrace(t)
			h.tofuCommand(t, project, "init", "-input=false", "-no-color")
			if operations := traceOperations(t, log); len(operations) != 0 {
				t.Fatalf("initialization invoked GPG: %v", operations)
			}
			h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
			assertEncrypted(t, filepath.Join(project, "terraform.tfstate"))
			clearTrace(t, log)
			if listed := h.tofuCommand(t, project, "state", "list"); !strings.Contains(listed, "terraform_data.example") {
				t.Fatal("state list did not recover the encrypted state")
			}
			operations := traceOperations(t, log)
			if operations["sign"] != 0 || operations["decrypt"] != 1 || operations["encrypt"] != 0 {
				t.Fatalf("state list must perform one decryption and no signing or encryption: %v", operations)
			}
			if output := h.tofuCommand(t, project, "output", "-raw", "secret"); output != string(message) {
				t.Fatalf("decrypted state output = %q", output)
			}
			h.migratePlaintext(t, project)
			h.tofuCommand(t, project, "plan", "-input=false", "-no-color", "-out=saved.tfplan")
			assertEncrypted(t, filepath.Join(project, "saved.tfplan"))
			if output := h.tofuCommand(t, project, "show", "-json", "saved.tfplan"); !strings.Contains(output, string(message)) {
				t.Fatal("saved plan could not be decrypted")
			}
			for _, attack := range []struct {
				file string
				args []string
			}{
				{"terraform.tfstate", []string{"state", "list"}},
				{"saved.tfplan", []string{"apply", "-input=false", "-no-color", "saved.tfplan"}},
			} {
				path := filepath.Join(project, attack.file)
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				forged := h.forgeEnvelope(t, original, firstHome, publicHome, first)
				if err := os.WriteFile(path, forged, 0600); err != nil {
					t.Fatal(err)
				}
				output, commandErr := h.runTofu(t, project, attack.args...)
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				if commandErr == nil || !strings.Contains(output, "valid binary signatures") {
					t.Fatalf("OpenTofu accepted a forged %s with enforced=true: err=%v\n%s", attack.file, commandErr, output)
				}
			}
			h.tofuCommand(t, project, "apply", "-input=false", "-no-color", "saved.tfplan")
			if usePolicy {
				h.writeProject(t, project, secondHome, true, first, second)
				h.tofuCommand(t, project, "apply", "-replace=terraform_data.gpg_rewrite", "-auto-approve", "-input=false", "-no-color")
				h.writeProject(t, project, secondHome, true, second)
				h.tofuCommand(t, project, "apply", "-replace=terraform_data.gpg_rewrite", "-auto-approve", "-input=false", "-no-color")
				if output := h.tofuCommand(t, project, "output", "-raw", "secret"); output != string(message) {
					t.Fatal("rotated state could not be read by the remaining member")
				}
				h.writeProject(t, project, firstHome, true, first, second)
				if output, err := h.runTofu(t, project, "state", "list"); err == nil || !strings.Contains(output, "GPG decryption failed") {
					t.Fatalf("removed member read rotated state: err=%v\n%s", err, output)
				}
			}
		})
	}

	t.Run("OpenTofu adds a policy provider to existing single-user encrypted state", func(t *testing.T) {
		project := t.TempDir()
		h.writeProject(t, project, firstHome, false)
		h.tofuCommand(t, project, "init", "-input=false", "-no-color")
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		h.writeProject(t, project, firstHome, true, first, second)
		if output := h.tofuCommand(t, project, "state", "list"); !strings.Contains(output, "terraform_data.example") {
			t.Fatal("adding a policy provider prevented reading existing state")
		}
		h.tofuCommand(t, project, "apply", "-replace=terraform_data.gpg_rewrite", "-auto-approve", "-input=false", "-no-color")
		h.writeProject(t, project, secondHome, true, first, second)
		if output := h.tofuCommand(t, project, "output", "-raw", "secret"); output != string(message) {
			t.Fatal("the added member could not read state after the policy migration")
		}
	})

	t.Run("OpenTofu remote GPG policy changes", h.testRemotePolicyChanges)

	t.Run("team example requires a nonempty authorized-key list", func(t *testing.T) {
		configuration, err := os.ReadFile(filepath.Join("..", "examples", "team", "main.tf"))
		if err != nil {
			t.Fatal(err)
		}
		binary, err := json.Marshal(h.binary)
		if err != nil {
			t.Fatal(err)
		}
		configuration = bytes.ReplaceAll(configuration, []byte(`"opentofu-gpg-encryption"`), binary)
		t.Setenv("GNUPGHOME", firstHome)
		t.Setenv("TF_VAR_gpg_authorized_keys", "[]")
		project := t.TempDir()
		if err := os.WriteFile(filepath.Join(project, "main.tf"), configuration, 0600); err != nil {
			t.Fatal(err)
		}
		h.tofuCommand(t, project, "init", "-input=false", "-no-color")
		output, err := h.runTofu(t, project, "plan", "-input=false", "-no-color")
		if err == nil || !strings.Contains(output, "Supply at least one full GPG primary-key fingerprint") {
			t.Fatalf("team example accepted empty authorization: err=%v\n%s", err, output)
		}
		keys, err := json.Marshal([]string{first, second})
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("TF_VAR_gpg_authorized_keys", string(keys))
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
	})
}

func executable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("integration tests require %s: %v", name, err)
	}
	return path
}

func tagged(payload []byte) []byte { return append([]byte(payloadPurpose), payload...) }

func (h harness) home(t *testing.T) string {
	t.Helper()
	parent := ""
	if runtime.GOOS == "darwin" {
		parent = "/tmp" // Keep GPG Unix-domain socket paths short on macOS.
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
	path := filepath.Join(home, "gpg.conf")
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err == nil {
		t.Cleanup(func() {
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Errorf("restore GPG configuration: %v", err)
			}
		})
	}
	if err := os.WriteFile(path, []byte("trust-model always\n"+options+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func (h harness) generateKey(t *testing.T, home, name string, options ...string) string {
	t.Helper()
	return h.generateKeyWithUsage(t, home, name, "sign,encr", "1d", options...)
}

func (h harness) generateKeyWithUsage(t *testing.T, home, name, usage, expiry string, options ...string) string {
	t.Helper()
	args := append([]string{"--pinentry-mode", "loopback", "--passphrase", ""}, options...)
	args = append(args, "--quick-generate-key", name, "rsa2048", usage, expiry)
	h.gpgCommand(t, home, nil, args...)
	listing := h.gpgCommand(t, home, nil, "--with-colons", "--list-keys", name)
	for line := range strings.SplitSeq(string(listing), "\n") {
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
	return h.gpgStreamCommand(t, home, bytes.NewReader(input), args...)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func (h harness) gpgStreamCommand(t *testing.T, home string, input io.Reader, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	args = append([]string{"--homedir", home, "--batch", "--no-tty", "--output", "-"}, args...)
	cmd := exec.CommandContext(ctx, h.gpg, args...)
	cmd.Stdin = input
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("GPG test setup/verification: %v\n%s", err, &stderr)
	}
	return output
}

func (h harness) decryptionStatus(t *testing.T, home string, ciphertext []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "2", "--output", "-", "--decrypt")
	cmd.Stdin = bytes.NewReader(ciphertext)
	cmd.Stdout = io.Discard
	var status bytes.Buffer
	cmd.Stderr = &status
	if err := cmd.Run(); err != nil {
		t.Fatalf("GPG status verification: %v\n%s", err, &status)
	}
	return status.Bytes()
}

func (h harness) exchange(t *testing.T, operation, input string, args ...string) ([]byte, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	args = append([]string{operation}, args...)
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
	reader := bufio.NewReader(stdout)
	header, err := reader.ReadString('\n')
	magic := "OpenTofu-External-Encryption-Method"
	if operation == "policy" {
		magic = "OpenTofu-External-Key-Provider"
	}
	if err != nil || header != fmt.Sprintf("{\"magic\":%q,\"version\":1}\n", magic) {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("invalid header before input: header=%q, err=%v\n%s", header, err, &stderr)
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

func methodInput(t *testing.T, payload, key []byte) string {
	t.Helper()
	input, err := json.Marshal(struct {
		Payload []byte `json:"payload"`
		Key     []byte `json:"key,omitempty"`
	}{payload, key})
	if err != nil {
		t.Fatal(err)
	}
	return string(input)
}

func (h harness) method(t *testing.T, operation, home string, payload, key []byte, args ...string) []byte {
	t.Helper()
	stdout, stderr, err := h.exchange(t, operation, methodInput(t, payload, key), h.methodOptions(home, key, args)...)
	if err != nil {
		t.Fatalf("%s request: %v\n%s", operation, err, stderr)
	}
	return decodeResponse[methodResponse](t, stdout).Payload
}

func (h harness) reject(t *testing.T, operation, home string, payload, key []byte, diagnostic string, args ...string) string {
	t.Helper()
	stdout, stderr, err := h.exchange(t, operation, methodInput(t, payload, key), h.methodOptions(home, key, args)...)
	if err == nil || !strings.Contains(stderr, diagnostic) || strings.Count(string(stdout), "\n") != 1 {
		t.Fatalf("expected rejected %s request containing %q: err=%v, stderr=%q", operation, diagnostic, err, stderr)
	}
	return stderr
}

func (h harness) methodOptions(home string, key []byte, args []string) []string {
	if key != nil {
		return args
	}
	return append([]string{"--gpg", h.gpg, "--homedir", home}, args...)
}

func (h harness) policy(t *testing.T, home, input string, args ...string) policyResponse {
	t.Helper()
	stdout, stderr, err := h.exchange(t, "policy", input, append([]string{"--gpg", h.gpg, "--homedir", home}, args...)...)
	if err != nil {
		t.Fatalf("policy request: %v\n%s", err, stderr)
	}
	return decodeResponse[policyResponse](t, stdout)
}

func decodeResponse[T any](t *testing.T, stdout []byte) T {
	t.Helper()
	_, body, _ := bytes.Cut(stdout, []byte("\n"))
	var result T
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

func (h harness) startTrace(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gpg-operations.log")
	clearTrace(t, path)
	t.Setenv(traceGPG, h.gpg)
	t.Setenv(traceLog, path)
	return path
}

func clearTrace(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func traceOperations(t *testing.T, path string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, operation := range strings.Fields(string(data)) {
		counts[operation]++
	}
	return counts
}

func (h harness) writeProject(t *testing.T, dir, home string, usePolicy bool, authorizedKeys ...string) {
	t.Helper()
	h.writeProjectConfig(t, dir, home, usePolicy, authorizedKeys, nil)
}

func (h harness) writeProjectConfig(t *testing.T, dir, home string, usePolicy bool, authorizedKeys, retiredKeys []string) {
	t.Helper()
	options := []string{"--gpg", h.wrapper, "--homedir", home}
	for _, fingerprint := range authorizedKeys {
		options = append(options, "--authorized-key", fingerprint)
	}
	for _, fingerprint := range retiredKeys {
		options = append(options, "--retired-key", fingerprint)
	}
	command := func(operation string, options []string) string {
		encoded, err := json.Marshal(append([]string{h.binary, operation}, options...))
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	var policyBlock, keys string
	methodOptions := options
	if usePolicy {
		policyBlock = fmt.Sprintf("key_provider \"external\" \"gpg_policy\" {\ncommand = %s\n}\n", command("policy", options))
		keys = "keys = key_provider.external.gpg_policy"
		methodOptions = nil
	}
	configuration := fmt.Sprintf(`terraform {
  encryption {
    %s
    method "external" "gpg" {
      %s
      encrypt_command = %s
      decrypt_command = %s
    }
    state {
      method   = method.external.gpg
      enforced = true
    }
    plan {
      method   = method.external.gpg
      enforced = true
    }
  }
}
resource "terraform_data" "example" {
  input = "integration-secret-sentinel"
}
resource "terraform_data" "gpg_rewrite" {}
output "secret" {
  value     = terraform_data.example.output
  sensitive = true
}
`, policyBlock, keys, command("encrypt", methodOptions), command("decrypt", methodOptions))
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
}

// Re-encrypt an otherwise valid payload using only a public key, omitting its
// authorized signature. This models a writer who can replace state or plans.
func (h harness) forgeEnvelope(t *testing.T, original []byte, ownerHome, publicHome, fingerprint string) []byte {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(original, &envelope); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := json.Unmarshal(envelope["encrypted_data"], &ciphertext); err != nil {
		t.Fatal(err)
	}
	message := h.gpgCommand(t, ownerHome, ciphertext, "--decrypt")
	defer clear(message)
	forged := h.gpgCommand(t, publicHome, message, "--recipient", fingerprint, "--encrypt")
	var err error
	envelope["encrypted_data"], err = json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func (h harness) migratePlaintext(t *testing.T, project string) {
	t.Helper()
	plaintext := h.tofuCommand(t, project, "state", "pull")
	path := filepath.Join(project, "main.tf")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	migration := strings.Replace(string(original), `    state {
      method   = method.external.gpg
      enforced = true
    }`, `    method "unencrypted" "migration" {}
    state {
      method = method.external.gpg
      fallback {
        method = method.unencrypted.migration
      }
    }`, 1)
	if migration == string(original) {
		t.Fatal("project fixture is missing its state encryption block")
	}
	if err := os.WriteFile(path, []byte(migration), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "terraform.tfstate"), []byte(plaintext), 0600); err != nil {
		t.Fatal(err)
	}
	h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
	assertEncrypted(t, filepath.Join(project, "terraform.tfstate"))
	if err := os.WriteFile(path, original, 0600); err != nil {
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
	if bytes.Contains(data, []byte("integration-secret-sentinel")) || !bytes.Contains(data, []byte("encrypted_data")) {
		t.Fatalf("%s is not an encrypted OpenTofu envelope", path)
	}
}

//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

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
	first := h.generateKey(t, master, "First Recipient <first@example.invalid>")
	second := h.generateKey(t, master, "Second Recipient <second@example.invalid>")
	firstHome, secondHome, publicHome := h.home(t), h.home(t), h.home(t)
	h.gpgCommand(t, firstHome, h.gpgCommand(t, master, nil, "--export-secret-keys", first), "--import")
	h.gpgCommand(t, secondHome, h.gpgCommand(t, master, nil, "--export-secret-keys", second), "--import")
	h.gpgCommand(t, publicHome, h.gpgCommand(t, master, nil, "--export", first, second), "--import")

	t.Run("default recipient and recovery", func(t *testing.T) {
		configure(t, master, "default-recipient "+first)
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
		if !bytes.Equal(direct, initial.Keys.EncryptionKey) {
			t.Fatal("metadata is not interoperable with direct GPG decryption")
		}
	})

	t.Run("default recipient self", func(t *testing.T) {
		configure(t, master, "default-key "+second+"\ndefault-recipient-self")
		result := h.request(t, master, "null")
		if got := h.gpgCommand(t, secondHome, result.Meta.ExternalData.EncryptedKey, "--decrypt"); !bytes.Equal(got, result.Keys.EncryptionKey) {
			t.Fatal("default-recipient-self did not select the default key")
		}
	})

	t.Run("explicit recipient overrides default", func(t *testing.T) {
		configure(t, master, "default-recipient "+second)
		result := h.request(t, master, "null", "--recipient", first)
		if got := h.gpgCommand(t, firstHome, result.Meta.ExternalData.EncryptedKey, "--decrypt"); !bytes.Equal(got, result.Keys.EncryptionKey) {
			t.Fatal("explicit recipient did not override the default")
		}
		_, _, err := h.exchange(t, secondHome, metadataJSON(t, result), "--recipient", second)
		if err == nil {
			t.Fatal("default recipient could decrypt an explicitly addressed key")
		}
	})

	t.Run("multiple recipients and public key only encryption", func(t *testing.T) {
		result := h.request(t, publicHome, "null", "--recipient", first, "--recipient", second)
		for _, home := range []string{firstHome, secondHome} {
			got := h.gpgCommand(t, home, result.Meta.ExternalData.EncryptedKey, "--decrypt")
			if !bytes.Equal(got, result.Keys.EncryptionKey) {
				t.Fatal("one of the recipients could not decrypt the wrapped key")
			}
		}
	})

	t.Run("configured extra recipients", func(t *testing.T) {
		configure(t, publicHome, "default-recipient "+first+"\nencrypt-to "+second)
		result := h.request(t, publicHome, "null", "--recipient", first)
		got := h.gpgCommand(t, secondHome, result.Meta.ExternalData.EncryptedKey, "--decrypt")
		if !bytes.Equal(got, result.Keys.EncryptionKey) {
			t.Fatal("GPG's configured encrypt-to recipient was not honored")
		}
	})

	t.Run("configured output cannot redirect protocol", func(t *testing.T) {
		unexpected := filepath.ToSlash(filepath.Join(t.TempDir(), "unexpected-key-output"))
		configure(t, master, "default-recipient "+first+"\noutput "+unexpected)
		h.request(t, master, "null")
		if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
			t.Fatalf("GPG wrote its configured output file: %v", err)
		}
	})

	t.Run("GNUPGHOME", func(t *testing.T) {
		configure(t, master, "default-recipient "+first)
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

	t.Run("missing recipient", func(t *testing.T) {
		home := h.home(t)
		stdout, stderr, err := h.exchange(t, home, "null")
		if err == nil || !strings.Contains(stderr, "recipient") || bytes.Contains(stdout, []byte("encryption_key")) {
			t.Fatalf("missing recipient: err=%v, stdout=%q, stderr=%q", err, stdout, stderr)
		}
	})

	t.Run("invalid ciphertext and missing secret key", func(t *testing.T) {
		valid := h.request(t, master, "null", "--recipient", first)
		for _, home := range []string{secondHome, publicHome} {
			if _, _, err := h.exchange(t, home, metadataJSON(t, valid), "--recipient", second); err == nil {
				t.Fatal("recovery succeeded without the recipient's private key")
			}
		}
		valid.Meta.ExternalData.EncryptedKey[len(valid.Meta.ExternalData.EncryptedKey)-1] ^= 1
		stdout, _, err := h.exchange(t, master, metadataJSON(t, valid), "--recipient", first)
		if err == nil || bytes.Contains(stdout, []byte("decryption_key")) {
			t.Fatal("tampered ciphertext returned key material")
		}
	})

	t.Run("GPG settings cannot bypass integrity checks or leak session keys", func(t *testing.T) {
		configure(t, master, "default-recipient "+first)
		ciphertext := h.gpgCommand(t, master, bytes.Repeat([]byte{42}, 32), "--rfc4880", "--recipient", first, "--encrypt")
		ciphertext[len(ciphertext)-1] ^= 1
		var result keyResponse
		result.Meta.ExternalData.Version = 1
		result.Meta.ExternalData.EncryptedKey = ciphertext
		configure(t, master, "default-recipient "+first+"\nignore-mdc-error\nshow-session-key")
		stdout, stderr, err := h.exchange(t, master, metadataJSON(t, result))
		if err == nil || bytes.Contains(stdout, []byte("decryption_key")) {
			t.Fatal("GPG's ignore-mdc-error setting bypassed integrity verification")
		}
		if strings.Contains(stderr, "SESSION_KEY") || strings.Contains(stderr, "session key") {
			t.Fatalf("GPG diagnostics exposed a session key: %s", stderr)
		}
		configure(t, master, "default-recipient "+first)
	})

	t.Run("reject unencrypted literal packet", func(t *testing.T) {
		literal := h.gpgCommand(t, master, bytes.Repeat([]byte{42}, 32), "--store")
		var result keyResponse
		result.Meta.ExternalData.Version = 1
		result.Meta.ExternalData.EncryptedKey = literal
		_, stderr, err := h.exchange(t, master, metadataJSON(t, result), "--recipient", first)
		if err == nil || !strings.Contains(stderr, "public-key decryption") {
			t.Fatalf("unencrypted literal packet: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("reject wrong key lengths", func(t *testing.T) {
		for _, size := range []int{16, 33, 4096} {
			var result keyResponse
			result.Meta.ExternalData.Version = 1
			result.Meta.ExternalData.EncryptedKey = h.gpgCommand(t, master, make([]byte, size), "--recipient", first, "--encrypt")
			if _, _, err := h.exchange(t, master, metadataJSON(t, result), "--recipient", first); err == nil {
				t.Fatalf("recovered a %d-byte key", size)
			}
		}
	})

	t.Run("timeout", func(t *testing.T) {
		_, stderr, err := h.exchange(t, master, "null", "--recipient", first, "--timeout", "1ns")
		if err == nil || !strings.Contains(stderr, "deadline exceeded") {
			t.Fatalf("timeout: err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("OpenTofu state plans and rotation", func(t *testing.T) {
		configure(t, firstHome, "default-recipient "+first)
		configure(t, secondHome, "default-recipient "+second)
		configure(t, master, "default-recipient "+first)
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
		h.tofuCommand(t, project, "apply", "-input=false", "-no-color", "saved.tfplan")

		// Changing the default affects new writes; the old private key still
		// recovers the input key from the previous state's metadata.
		configure(t, master, "default-recipient "+second)
		h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
		h.writeProject(t, project, secondHome)
		if value := h.tofuCommand(t, project, "output", "-raw", "secret"); value != "integration-secret-sentinel" {
			t.Fatal("rotated state could not be read with the new private key alone")
		}
		h.writeProject(t, project, firstHome)
		cmd := exec.CommandContext(t.Context(), h.tofu, "output", "-raw", "secret")
		cmd.Dir = project
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("old recipient could read rotated state: %s", output)
		}
	})
}

func (h harness) home(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "keyring with spaces")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
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

func (h harness) generateKey(t *testing.T, home, name string) string {
	t.Helper()
	h.gpgCommand(t, home, nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", name, "rsa2048", "encr", "1d")
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

func (h harness) writeProject(t *testing.T, dir, home string) {
	t.Helper()
	command, err := json.Marshal([]string{h.binary, "--gpg", h.gpg, "--homedir", home})
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
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.tofu, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tofu %s (%s): %v\n%s", strings.Join(args, " "), runtime.GOOS, err, output)
	}
	return string(output)
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

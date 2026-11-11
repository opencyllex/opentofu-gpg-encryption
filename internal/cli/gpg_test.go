package cli_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"opentofu-gpg-key-provider/internal/cli"
)

const gpgTestStderr = "OPENTOFU_GPG_TEST_STDERR"

func TestMain(m *testing.M) {
	// The test executable doubles as GPG to provide deterministic, translated
	// diagnostics through the CLI's normal subprocess boundary.
	if stderr, ok := os.LookupEnv(gpgTestStderr); ok {
		io.WriteString(os.Stderr, stderr)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func TestGPGFailureDiagnostics(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	firstKey := strings.Repeat("0123456789ABCDEF", 4)
	secondKey := strings.Repeat("FEDCBA9876543210", 4)
	failure := "gpg: échec de la vérification d'intégrité"
	note := "gpg: session key could not be verified"
	for _, test := range []struct {
		name string
		log  string
	}{
		{"ordinary failure", ""},
		{"log before status", "gpg: clé de session : '9:" + firstKey + "'\n[GNUPG:] SESSION_KEY 9:" + firstKey + "\n"},
		{"log after status", "[GNUPG:] SESSION_KEY 9:" + firstKey + "\ngpg: сеансовый ключ: '9:" + firstKey + "'\n"},
		{"bare key value", "[GNUPG:] SESSION_KEY 9:" + firstKey + "\ngpg: clé de session : '" + firstKey + "'\n"},
		{"multiple session keys", "gpg: clé de session : '9:" + firstKey + "'\r\n[GNUPG:] SESSION_KEY 9:" + firstKey + "\r\n[GNUPG:] SESSION_KEY 9:" + secondKey + "\r\ngpg: сеансовый ключ: '9:" + secondKey + "'\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(gpgTestStderr, test.log+failure+"\n"+note+"\n[GNUPG:] FAILURE decrypt 1\n")
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{"--gpg", executable}, strings.NewReader(`{"external_data":{"version":1,"encrypted_key":"AQ=="}}`), &stdout, &stderr, "dev")
			if code != 1 {
				t.Fatalf("exit code = %d, stderr = %q", code, &stderr)
			}
			for _, want := range []string{failure, note} {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("GPG diagnostic %q was lost: %s", want, &stderr)
				}
			}
			for _, secret := range []string{firstKey, secondKey, "SESSION_KEY"} {
				if strings.Contains(stderr.String(), secret) {
					t.Fatalf("GPG diagnostics exposed session-key data: %s", &stderr)
				}
			}
			if stdout.String() != "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n" {
				t.Fatalf("unexpected protocol output: %q", &stdout)
			}
		})
	}
}

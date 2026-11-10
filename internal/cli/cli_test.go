package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"opentofu-gpg-key-provider/internal/cli"
)

func TestHelpAndVersion(t *testing.T) {
	for _, flag := range []string{"--help", "--version"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{flag}, strings.NewReader(""), &stdout, &stderr, "1.2.3")
			if code != 0 {
				t.Fatalf("exit code = %d; stderr: %s", code, &stderr)
			}
			if strings.Contains(stdout.String(), "OpenTofu-External-Key-Provider") {
				t.Fatal("informational command emitted a protocol header")
			}
			if flag == "--version" && stdout.String() != "opentofu-gpg-key-provider 1.2.3\n" {
				t.Fatalf("version output: %s", &stdout)
			}
			if flag == "--help" && !strings.Contains(stderr.String(), "default-recipient") {
				t.Fatalf("help does not explain optional recipients: %s", &stderr)
			}
		})
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--unknown"}, {"--timeout", "0s"}, {"--timeout", "-1s"},
		{"--recipient", ""}, {"--recipient"}, {"--gpg", ""}, {"positional"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), args, strings.NewReader("null"), &stdout, &stderr, "dev")
			if code != 2 || stderr.Len() == 0 || stdout.Len() != 0 {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, &stdout, &stderr)
			}
		})
	}
}

func TestMissingGPG(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run(t.Context(), []string{"--gpg", "nonexistent-gpg-for-test"}, strings.NewReader("null"), &stdout, &stderr, "dev")
	if code != 1 || stderr.Len() == 0 {
		t.Fatalf("code = %d, stderr = %q", code, &stderr)
	}
	if !strings.HasPrefix(stdout.String(), `{"magic":"OpenTofu-External-Key-Provider","version":1}`+"\n") {
		t.Fatalf("missing protocol header: %q", &stdout)
	}
	if strings.Contains(stdout.String(), "encryption_key") {
		t.Fatal("failed request returned key material")
	}
}

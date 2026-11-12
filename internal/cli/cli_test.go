package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/opencyllex/opentofu-gpg-encryption/internal/cli"
)

func TestHelpAndVersion(t *testing.T) {
	for _, flag := range []string{"--help", "--version"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{flag}, strings.NewReader(""), &stdout, &stderr, "1.2.3")
			if code != 0 {
				t.Fatalf("exit code = %d; stderr: %s", code, &stderr)
			}
			if strings.Contains(stdout.String(), "OpenTofu-External-") {
				t.Fatal("informational command emitted a protocol header")
			}
			if flag == "--version" && stdout.String() != "opentofu-gpg-encryption 1.2.3\n" {
				t.Fatalf("version output: %s", &stdout)
			}
			if flag == "--help" && (!strings.Contains(stderr.String(), "<encrypt|decrypt|policy>") || !strings.Contains(stderr.String(), "sole eligible signing key")) {
				t.Fatalf("help does not explain signer selection and default authorization: %s", &stderr)
			}
		})
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--unknown"}, {"encrypt", "--timeout", "0s"}, {"decrypt", "--timeout", "-1s"},
		{"policy", "--authorized-key", ""}, {"policy", "--authorized-key"}, {"encrypt", "--gpg", ""}, {"positional"},
		{"encrypt", "--recipient", strings.Repeat("A", 40)},
		{"policy", "--authorized-key", "person@example.invalid"},
		{"policy", "--authorized-key", "0123456789ABCDEF"},
		{"policy", "--authorized-key", strings.Repeat("G", 40)},
		{"policy", "--authorized-key", "0x" + strings.Repeat("A", 40)},
		{"policy", "--authorized-key", strings.Repeat("A", 40) + "!"},
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
	code := cli.Run(t.Context(), []string{"encrypt", "--gpg", "nonexistent-gpg-for-test"}, strings.NewReader(`{"payload":"AQ=="}`), &stdout, &stderr, "dev")
	if code != 1 || stderr.Len() == 0 {
		t.Fatalf("code = %d, stderr = %q", code, &stderr)
	}
	if !strings.HasPrefix(stdout.String(), `{"magic":"OpenTofu-External-Encryption-Method","version":1}`+"\n") {
		t.Fatalf("missing protocol header: %q", &stdout)
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Fatal("failed request returned a payload")
	}
}

func TestCancellationWhileWaitingForEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stdin, input := io.Pipe()
	defer stdin.Close()
	defer input.Close()
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, []string{"encrypt"}, stdin, &stdout, &stderr, "dev")
	}()
	if _, err := io.WriteString(input, `{"payload":"AQ=="}`); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case code := <-done:
		if code != 1 || !strings.Contains(stderr.String(), context.Canceled.Error()) {
			t.Fatalf("code = %d, stderr = %q", code, &stderr)
		}
		if stdout.String() != "{\"magic\":\"OpenTofu-External-Encryption-Method\",\"version\":1}\n" {
			t.Fatalf("unexpected protocol output: %q", &stdout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not stop the command while stdin remained open")
	}
}

func TestInvalidMethodRequests(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, input := range []string{
		"", "{", "null", "[]", "{}", `{"payload":null}`,
		`{"payload":[1,2,3]}`, `{"payload":"!"}`,
		`{"Payload":"AQ=="}`, `{"payload":"AQ==","unknown":true}`,
		`{"payload":"AQ==","payload":"Ag=="}`,
		`{"payload":"AQ==","\u0070ayload":"Ag=="}`,
		`{"payload":"AQ=="} null`, `{"payload":"AQ==","key":"!"}`,
		`{"payload":"AQ==","key":""}`,
	} {
		t.Run(input, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{"decrypt"}, strings.NewReader(input), &stdout, &stderr, "dev")
			if code != 1 || strings.Contains(stderr.String(), "list local GPG keys:") || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("invalid method request: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
			}
		})
	}
}

func TestInvalidPolicies(t *testing.T) {
	for _, encoded := range []string{
		`{}`, `null`, `{"version":2,"gpg":"must-not-run-gpg"}`,
		`{"version":2,"authorized_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":1,"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":1,"authorized_keys":[],"gpg":"must-not-run-gpg","homedir":null}`,
		`{"version":1,"authorized_keys":[],"gpg":"","homedir":""}`,
		`{"version":1,"gpg":"must-not-run-gpg","authorized_keys":["person@example.invalid"],"homedir":""}`,
		`{"version":1,"gpg":"must-not-run-gpg","unknown":true}`,
		`{"version":1,"version":1,"gpg":"must-not-run-gpg"}`,
	} {
		input, err := json.Marshal(map[string]string{"payload": "AQ==", "key": base64.StdEncoding.EncodeToString([]byte(encoded))})
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.Run(t.Context(), []string{"decrypt"}, bytes.NewReader(input), &stdout, &stderr, "dev")
		if code != 1 || !strings.Contains(stderr.String(), "parse GPG policy") || strings.Count(stdout.String(), "\n") != 1 {
			t.Fatalf("invalid policy: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
		}
	}
}

func TestMethodRejectsFlagsWithPolicy(t *testing.T) {
	policy := []byte(`{"version":1,"authorized_keys":[],"gpg":"must-not-run-gpg","homedir":""}`)
	input, err := json.Marshal(map[string][]byte{"payload": {1}, "key": policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"encrypt", "decrypt"} {
		for _, options := range [][]string{
			{"--authorized-key", strings.Repeat("A", 40)},
			{"--gpg", "gpg"},
			{"--homedir", ""},
		} {
			t.Run(operation+" "+options[0], func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := cli.Run(t.Context(), append([]string{operation}, options...), bytes.NewReader(input), &stdout, &stderr, "dev")
				if code != 1 || !strings.Contains(stderr.String(), options[0]+" cannot be used with a policy key") || strings.Count(stdout.String(), "\n") != 1 {
					t.Fatalf("conflicting method flag: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
				}
			})
		}
	}
}

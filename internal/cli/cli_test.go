package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
		{"policy", "--retired-key"},
		{"policy", "--retired-key", ""},
		{"policy", "--retired-key", "person@example.invalid"},
		{"policy", "--retired-key", "0123456789ABCDEF"},
		{"policy", "--retired-key", strings.Repeat("G", 40)},
		{"policy", "--retired-key", "0x" + strings.Repeat("A", 40)},
		{"policy", "--retired-key", strings.Repeat("A", 40) + "!"},
		{"policy", "--authorized-key", strings.Repeat("A", 40), "--retired-key", strings.Repeat("a", 40)},
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

func TestInvalidFingerprintDiagnostics(t *testing.T) {
	for _, keys := range []struct {
		option string
		field  string
	}{
		{"--authorized-key", "authorized_keys"},
		{"--retired-key", "retired_keys"},
	} {
		for _, value := range []string{"ABCDEF", strings.Repeat("G", 40)} {
			t.Run(keys.option+" "+value, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := cli.Run(t.Context(), []string{"policy", keys.option, value}, strings.NewReader("null"), &stdout, &stderr, "dev")
				if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), keys.option+": ") || !strings.Contains(stderr.String(), `"`+value+`"`) || !strings.Contains(stderr.String(), "fingerprint") {
					t.Fatalf("invalid fingerprint lost its diagnostic context: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
				}
			})
			t.Run(keys.field+" "+value, func(t *testing.T) {
				config := map[string]any{
					"version": 2, "authorized_keys": []string{}, "retired_keys": []string{},
					"gpg": "must-not-run-gpg", "homedir": "",
				}
				config[keys.field] = []string{value}
				policy, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				input, err := json.Marshal(map[string][]byte{"payload": {1}, "key": policy})
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(t.Context(), []string{"decrypt"}, bytes.NewReader(input), &stdout, &stderr, "dev")
				if code != 1 || stdout.String() != "{\"magic\":\"OpenTofu-External-Encryption-Method\",\"version\":1}\n" ||
					!strings.Contains(stderr.String(), "parse GPG policy: "+keys.field+": ") ||
					!strings.Contains(stderr.String(), `"`+value+`"`) || !strings.Contains(stderr.String(), "fingerprint") ||
					strings.Contains(stderr.String(), "--authorized-key") || strings.Contains(stderr.String(), "--retired-key") {
					t.Fatalf("invalid policy fingerprint lost its field context: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
				}
			})
		}
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	dir, name := t.TempDir(), "gpg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), binary, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	const unexpectedGPG = "unexpected GPG invocation"
	t.Setenv(gpgTestStderr, unexpectedGPG)
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
			if code != 1 || strings.Contains(stderr.String(), unexpectedGPG) || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("invalid method request: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
			}
		})
	}
}

func TestInvalidPolicies(t *testing.T) {
	for _, encoded := range []string{
		`{}`, `null`, `{"version":2,"gpg":"must-not-run-gpg"}`,
		`{"version":2,"authorized_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":null}`,
		`{"version":2,"authorized_keys":[],"retired_keys":[],"gpg":"","homedir":""}`,
		`{"version":2,"authorized_keys":["person@example.invalid"],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":"","unknown":true}`,
		`{"version":2,"version":2,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":3,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":1,"authorized_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":1,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"allow_revoked_signers":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":null,"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":"not-an-array","gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":["person@example.invalid"],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"Retired_Keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":[],"retired_keys":[],"\u0072etired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`,
		`{"version":2,"authorized_keys":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],"retired_keys":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"gpg":"must-not-run-gpg","homedir":""}`,
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
	policy := []byte(`{"version":2,"authorized_keys":[],"retired_keys":[],"gpg":"must-not-run-gpg","homedir":""}`)
	input, err := json.Marshal(map[string][]byte{"payload": {1}, "key": policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"encrypt", "decrypt"} {
		for _, options := range [][]string{
			{"--authorized-key", strings.Repeat("A", 40)},
			{"--retired-key", strings.Repeat("B", 40)},
			{"--gpg", "gpg"},
			{"--homedir", ""},
		} {
			t.Run(operation+" "+options[0], func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := cli.Run(t.Context(), append([]string{operation}, options...), bytes.NewReader(input), &stdout, &stderr, "dev")
				if code != 1 || !strings.Contains(stderr.String(), options[0]+" cannot be used on a method command with a policy key") || strings.Count(stdout.String(), "\n") != 1 {
					t.Fatalf("conflicting method flag: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
				}
			})
		}
	}
}

func TestDisabledVersionFlagWithPolicy(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(map[string]any{
		"version": 2, "authorized_keys": []string{strings.Repeat("A", 40)},
		"retired_keys": []string{}, "gpg": executable, "homedir": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string][]byte{"payload": {1}, "key": policy})
	if err != nil {
		t.Fatal(err)
	}
	const invoked = "GPG received the request"
	t.Setenv(gpgTestStderr, invoked)
	for _, operation := range []string{"encrypt", "decrypt"} {
		t.Run(operation, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{operation, "--version=false"}, bytes.NewReader(input), &stdout, &stderr, "dev")
			if code != 1 || !strings.Contains(stderr.String(), invoked) || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("disabled version flag blocked the policy request: code=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
			}
		})
	}
}

func TestRetiredKeyPolicyConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run(t.Context(), []string{
		"policy", "--gpg", "nonexistent-gpg-policy-must-not-run",
		"--authorized-key", strings.Repeat("a", 40),
		"--retired-key", strings.Repeat("b", 40),
		"--retired-key", strings.Repeat("c", 64),
	}, strings.NewReader(`{"external_data":{"policy_version":1}}`), &stdout, &stderr, "dev")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, &stderr)
	}
	_, body, _ := bytes.Cut(stdout.Bytes(), []byte("\n"))
	var response struct {
		Keys struct {
			EncryptionKey []byte `json:"encryption_key"`
			DecryptionKey []byte `json:"decryption_key"`
		} `json:"keys"`
		Meta json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Version        int      `json:"version"`
		AuthorizedKeys []string `json:"authorized_keys"`
		RetiredKeys    []string `json:"retired_keys"`
	}
	if err := json.Unmarshal(response.Keys.DecryptionKey, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != 2 || len(policy.AuthorizedKeys) != 1 || policy.AuthorizedKeys[0] != strings.Repeat("A", 40) ||
		len(policy.RetiredKeys) != 2 || policy.RetiredKeys[0] != strings.Repeat("B", 40) || policy.RetiredKeys[1] != strings.Repeat("C", 64) {
		t.Fatalf("unexpected retired-key policy: %+v", policy)
	}
	if !bytes.Equal(response.Keys.EncryptionKey, response.Keys.DecryptionKey) || string(response.Meta) != `{"external_data":{"policy_version":1}}` {
		t.Fatalf("unexpected policy keys or stored metadata: %s", body)
	}
}

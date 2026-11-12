package provider_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/policy"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/provider"
)

type output struct {
	Keys struct {
		EncryptionKey []byte `json:"encryption_key"`
		DecryptionKey []byte `json:"decryption_key"`
	} `json:"keys"`
	Meta json.RawMessage `json:"meta"`
}

func TestHeaderBeforeInput(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	t.Cleanup(func() {
		inputReader.Close()
		inputWriter.Close()
		outputReader.Close()
		outputWriter.Close()
	})
	done := make(chan error, 1)
	go func() {
		done <- provider.Run(t.Context(), inputReader, outputWriter, configuration("A"))
		outputWriter.Close()
	}()
	header := make(chan string, 1)
	reader := bufio.NewReader(outputReader)
	go func() {
		line, _ := reader.ReadString('\n')
		header <- line
	}()
	select {
	case line := <-header:
		if line != "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n" {
			t.Fatalf("invalid header: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy provider did not send its header before input")
	}
	if _, err := io.WriteString(inputWriter, "null"); err != nil {
		t.Fatal(err)
	}
	inputWriter.Close()
	var result output
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	checkPolicy(t, result.Keys.EncryptionKey, "A")
}

func TestPolicyAlwaysComesFromCurrentConfiguration(t *testing.T) {
	initial := request(t, "null", configuration("A"))
	if initial.Keys.DecryptionKey != nil {
		t.Fatal("encryption-only request included a decryption policy")
	}
	checkPolicy(t, initial.Keys.EncryptionKey, "A")
	if bytes.Contains(initial.Meta, []byte(strings.Repeat("A", 40))) {
		t.Fatal("authorization was persisted in metadata instead of current configuration")
	}
	current := request(t, string(initial.Meta), configuration("B"))
	checkPolicy(t, current.Keys.EncryptionKey, "B")
	checkPolicy(t, current.Keys.DecryptionKey, "B")
}

func TestInvalidMetadata(t *testing.T) {
	for _, input := range []string{
		"", "{", "[]", "null null", "{}", `{"external_data":null}`,
		`{"external_data":{}}`,
		`{"external_data":{"policy_version":2}}`,
		`{"external_data":{"version":1,"encrypted_key":"AQ=="}}`,
		`{"external_data":{"policy_version":1,"authorized_keys":["attacker"]}}`,
		`{"extra":1,"external_data":{"policy_version":1}}`,
		`{"External_Data":{"policy_version":1}}`,
		`{"external_data":{"POLICY_VERSION":1}}`,
		`{"external_data":null,"external_data":{"policy_version":1}}`,
		`{"external_data":{"policy_version":0,"policy_version":1}}`,
		`{"external_data":{"policy_version":0,"\u0070olicy_version":1}}`,
		`{"external_data":{"policy_version":1}} null`,
	} {
		t.Run(input, func(t *testing.T) {
			var stdout bytes.Buffer
			err := provider.Run(t.Context(), strings.NewReader(input), &stdout, configuration("A"))
			if err == nil || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("invalid metadata: err=%v, stdout=%q", err, &stdout)
			}
		})
	}
}

func TestMetadataSizeLimit(t *testing.T) {
	var stdout bytes.Buffer
	err := provider.Run(t.Context(), strings.NewReader(strings.Repeat(" ", 1024*1024+1)), &stdout, configuration("A"))
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func configuration(hex string) policy.Config {
	return policy.Config{Version: 1, AuthorizedKeys: []string{strings.Repeat(hex, 40)}, GPG: "nonexistent-gpg-policy-must-not-run", HomeDir: "configured home"}
}

func checkPolicy(t *testing.T, data []byte, hex string) {
	t.Helper()
	var config policy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || len(config.AuthorizedKeys) != 1 || config.AuthorizedKeys[0] != strings.Repeat(hex, 40) || config.GPG != "nonexistent-gpg-policy-must-not-run" || config.HomeDir != "configured home" {
		t.Fatalf("unexpected policy: %+v", config)
	}
}

func request(t *testing.T, input string, config policy.Config) output {
	t.Helper()
	var stdout bytes.Buffer
	if err := provider.Run(t.Context(), strings.NewReader(input), &stdout, config); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&stdout)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	var result output
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

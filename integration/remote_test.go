//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This backend keeps only encrypted snapshots. Its lock protocol is exercised
// by the real OpenTofu HTTP backend, including the lock ID on state uploads.
type httpStateBackend struct {
	url     string
	mu      sync.Mutex
	state   []byte
	uploads [][]byte
	lockID  string
	lock    []byte
	locks   int
	unlocks int
}

func newHTTPStateBackend(t *testing.T) *httpStateBackend {
	t.Helper()
	backend := &httpStateBackend{}
	server := httptest.NewServer(http.HandlerFunc(backend.serveHTTP))
	backend.url = server.URL
	t.Cleanup(func() {
		server.Close()
		backend.mu.Lock()
		defer backend.mu.Unlock()
		if backend.lockID != "" || backend.locks == 0 || backend.locks != backend.unlocks {
			t.Errorf("unbalanced remote locking: held=%q, locks=%d, unlocks=%d", backend.lockID, backend.locks, backend.unlocks)
		}
		var previous stateEnvelope
		for i, upload := range backend.uploads {
			current := decodeStateEnvelope(t, upload)
			if i > 0 && (current.Lineage != previous.Lineage || current.Serial <= previous.Serial) {
				t.Errorf("remote upload %d changed lineage or did not increase serial", i)
			}
			previous = current
		}
	})
	return backend
}

func (b *httpStateBackend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/state" && r.Method == http.MethodGet:
		if len(b.state) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(b.state)
	case r.URL.Path == "/state" && r.Method == http.MethodPost:
		if b.lockID == "" || r.URL.Query().Get("ID") != b.lockID {
			w.WriteHeader(http.StatusLocked)
			return
		}
		b.state = bytes.Clone(body)
		b.uploads = append(b.uploads, bytes.Clone(body))
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/lock" && (r.Method == "LOCK" || r.Method == "UNLOCK"):
		var info struct{ ID string }
		if err := json.Unmarshal(body, &info); err != nil || info.ID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == "LOCK" {
			if b.lockID != "" {
				w.WriteHeader(http.StatusLocked)
				w.Write(b.lock)
				return
			}
			b.lockID, b.lock = info.ID, bytes.Clone(body)
			b.locks++
		} else {
			if b.lockID != info.ID {
				w.WriteHeader(http.StatusConflict)
				w.Write(b.lock)
				return
			}
			b.lockID, b.lock = "", nil
			b.unlocks++
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (b *httpStateBackend) snapshot() ([]byte, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.state), len(b.uploads)
}

func (h harness) remoteProject(t *testing.T, home string, authorized []string) (string, *httpStateBackend) {
	t.Helper()
	backend := newHTTPStateBackend(t)
	project := t.TempDir()
	h.writeProject(t, project, home, true, authorized...)
	configuration := fmt.Sprintf(`terraform {
  backend "http" {
    address        = %q
    lock_address   = %q
    unlock_address = %q
    lock_method    = "LOCK"
    unlock_method  = "UNLOCK"
  }
}
`, backend.url+"/state", backend.url+"/lock", backend.url+"/lock")
	if err := os.WriteFile(filepath.Join(project, "backend.tf"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	h.tofuCommand(t, project, "init", "-input=false", "-no-color")
	h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
	return project, backend
}

type stateEnvelope struct {
	Lineage           string `json:"lineage"`
	Serial            uint64 `json:"serial"`
	EncryptionVersion string `json:"encryption_version"`
	Payload           []byte `json:"encrypted_data"`
}

func decodeStateEnvelope(t *testing.T, data []byte) stateEnvelope {
	t.Helper()
	var envelope stateEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.EncryptionVersion == "" || len(envelope.Payload) == 0 || envelope.Lineage == "" || bytes.Contains(data, []byte("integration-secret-sentinel")) {
		t.Fatal("the HTTP backend received unencrypted or invalid state")
	}
	return envelope
}

type projectSnapshot struct {
	lineage   string
	serial    uint64
	rewriteID string
	example   json.RawMessage
}

func (h harness) projectSnapshot(t *testing.T, project string) projectSnapshot {
	t.Helper()
	var state struct {
		Lineage string
		Serial  uint64
		Outputs struct {
			Secret struct{ Value string }
		}
		Resources []struct {
			Type, Name string
			Instances  []struct{ Attributes json.RawMessage }
		}
	}
	if err := json.Unmarshal([]byte(h.tofuCommand(t, project, "state", "pull")), &state); err != nil {
		t.Fatal(err)
	}
	snapshot := projectSnapshot{lineage: state.Lineage, serial: state.Serial}
	for _, resource := range state.Resources {
		if resource.Type != "terraform_data" || len(resource.Instances) != 1 {
			t.Fatal("the remote fixture lost its application or rewrite resource")
		}
		attributes := resource.Instances[0].Attributes
		switch resource.Name {
		case "example":
			snapshot.example = attributes
		case "gpg_rewrite":
			var instance struct{ ID string }
			if err := json.Unmarshal(attributes, &instance); err != nil {
				t.Fatal(err)
			}
			snapshot.rewriteID = instance.ID
		}
	}
	if snapshot.lineage == "" || snapshot.serial == 0 || snapshot.rewriteID == "" || len(snapshot.example) == 0 || state.Outputs.Secret.Value != "integration-secret-sentinel" {
		t.Fatal("the remote fixture lost its lineage, serial, replacement ID, or application data")
	}
	return snapshot
}

func (h harness) unchangedRemoteApply(t *testing.T, project string, backend *httpStateBackend) {
	t.Helper()
	before, writes := backend.snapshot()
	h.tofuCommand(t, project, "apply", "-auto-approve", "-input=false", "-no-color")
	after, currentWrites := backend.snapshot()
	if currentWrites != writes || !bytes.Equal(before, after) {
		t.Fatal("a policy-only no-change apply uploaded or changed remote ciphertext")
	}
}

func (h harness) rewriteRemoteState(t *testing.T, project string, backend *httpStateBackend, before projectSnapshot) projectSnapshot {
	t.Helper()
	oldCiphertext, writes := backend.snapshot()
	h.tofuCommand(t, project, "apply", "-replace=terraform_data.gpg_rewrite", "-auto-approve", "-input=false", "-no-color")
	ciphertext, currentWrites := backend.snapshot()
	after := h.projectSnapshot(t, project)
	if currentWrites <= writes || bytes.Equal(oldCiphertext, ciphertext) {
		t.Fatal("replacing gpg_rewrite did not upload fresh remote ciphertext")
	}
	if after.serial <= before.serial || after.lineage != before.lineage || after.rewriteID == before.rewriteID || !bytes.Equal(after.example, before.example) {
		t.Fatal("the rewrite did not increase serial and replace gpg_rewrite while preserving lineage and application data")
	}
	envelope := decodeStateEnvelope(t, ciphertext)
	if envelope.Lineage != after.lineage || envelope.Serial != after.serial {
		t.Fatal("encrypted envelope metadata does not match the recovered state")
	}
	return after
}

func (h harness) testRemotePolicyChanges(t *testing.T) {
	master := h.home(t)
	first := h.generateKey(t, master, "Remote First <remote-first@example.invalid>")
	second := h.generateKey(t, master, "Remote Second <remote-second@example.invalid>")
	firstHome, secondHome := h.home(t), h.home(t)
	public := h.gpgCommand(t, master, nil, "--export", first, second)
	for home, fingerprint := range map[string]string{firstHome: first, secondHome: second} {
		h.gpgCommand(t, home, h.gpgCommand(t, master, nil, "--export-secret-keys", fingerprint), "--import")
		h.gpgCommand(t, home, public, "--import")
	}
	both := []string{first, second}
	bothOptions := []string{"--authorized-key", first, "--authorized-key", second}

	t.Run("add and remove recipients with forced rewrites", func(t *testing.T) {
		project, backend := h.remoteProject(t, firstHome, []string{first})
		state := h.projectSnapshot(t, project)
		h.writeProject(t, project, firstHome, true, both...)
		h.unchangedRemoteApply(t, project, backend)
		stored, _ := backend.snapshot()
		h.reject(t, "decrypt", secondHome, decodeStateEnvelope(t, stored).Payload, nil, "GPG decryption failed", bothOptions...)
		state = h.rewriteRemoteState(t, project, backend, state)
		stored, _ = backend.snapshot()
		if recovered := h.method(t, "decrypt", secondHome, decodeStateEnvelope(t, stored).Payload, nil, bothOptions...); !bytes.Contains(recovered, []byte("integration-secret-sentinel")) {
			t.Fatal("the added recipient could not read the application data")
		}

		// First removal rewrite changes the signer while keeping both recipients.
		h.writeProject(t, project, secondHome, true, both...)
		h.unchangedRemoteApply(t, project, backend)
		stored, _ = backend.snapshot()
		h.reject(t, "decrypt", secondHome, decodeStateEnvelope(t, stored).Payload, nil, "signature from key "+first+" is not authorized", "--authorized-key", second)
		state = h.rewriteRemoteState(t, project, backend, state)
		stored, _ = backend.snapshot()
		h.method(t, "decrypt", secondHome, decodeStateEnvelope(t, stored).Payload, nil, "--authorized-key", second)
		h.method(t, "decrypt", firstHome, decodeStateEnvelope(t, stored).Payload, nil, bothOptions...)

		// Second removal rewrite excludes the retired encryption recipient.
		h.writeProject(t, project, secondHome, true, second)
		h.unchangedRemoteApply(t, project, backend)
		h.rewriteRemoteState(t, project, backend, state)
		stored, _ = backend.snapshot()
		h.reject(t, "decrypt", firstHome, decodeStateEnvelope(t, stored).Payload, nil, "GPG decryption failed", "--authorized-key", second)
	})

	t.Run("recover a revoked signer and remove the exception", func(t *testing.T) {
		project, backend := h.remoteProject(t, firstHome, both)
		state := h.projectSnapshot(t, project)
		original, writes := backend.snapshot()
		h.gpgCommand(t, firstHome, []byte("revkey\ny\n0\n\ny\nsave\n"), "--command-fd", "0", "--pinentry-mode", "loopback", "--passphrase", "", "--edit-key", first)
		h.gpgCommand(t, secondHome, h.gpgCommand(t, firstHome, nil, "--export", first), "--import")
		h.writeProject(t, project, secondHome, true, both...)
		if output, err := h.runTofu(t, project, "state", "list"); err == nil || !strings.Contains(output, "has been revoked") {
			t.Fatalf("normal remote reads accepted a revoked signer: err=%v\n%s", err, output)
		}
		unchanged, currentWrites := backend.snapshot()
		if currentWrites != writes || !bytes.Equal(original, unchanged) {
			t.Fatal("a rejected read modified remote state")
		}

		h.writeProjectConfig(t, project, secondHome, true, []string{second}, []string{first})
		h.unchangedRemoteApply(t, project, backend)
		h.projectSnapshot(t, project) // Inspect the original state using recovery authorization.
		state = h.rewriteRemoteState(t, project, backend, state)
		stored, _ := backend.snapshot()
		h.method(t, "decrypt", secondHome, decodeStateEnvelope(t, stored).Payload, nil, "--authorized-key", second)
		h.reject(t, "decrypt", firstHome, decodeStateEnvelope(t, stored).Payload, nil, "GPG decryption failed", "--authorized-key", second)

		h.writeProject(t, project, secondHome, true, second)
		h.unchangedRemoteApply(t, project, backend)
		h.rewriteRemoteState(t, project, backend, state)
		h.tofuCommand(t, project, "state", "list")
		h.reject(t, "decrypt", secondHome, decodeStateEnvelope(t, original).Payload, nil, "has been revoked", bothOptions...)
	})

	t.Run("retire an expired unrevoked signer and remove its read authorization", func(t *testing.T) {
		retiredHome, currentHome := h.home(t), h.home(t)
		created := time.Now().Add(-48 * time.Hour)
		fakeTime := strconv.FormatInt(created.Unix(), 10)
		retired := h.generateKey(t, retiredHome, "Remote Expired <remote-expired@example.invalid>", "--faked-system-time", fakeTime)
		current := h.generateKeyWithUsage(t, currentHome, "Remote Current <remote-current@example.invalid>", "sign,encr", "2y", "--faked-system-time", fakeTime)
		h.gpgCommand(t, retiredHome, h.gpgCommand(t, currentHome, nil, "--export", current), "--import")
		h.gpgCommand(t, currentHome, h.gpgCommand(t, retiredHome, nil, "--export", retired), "--import")
		configure(t, retiredHome, "faked-system-time "+strconv.FormatInt(created.Add(time.Hour).Unix(), 10))
		project, backend := h.remoteProject(t, retiredHome, []string{retired, current})
		state := h.projectSnapshot(t, project)
		original, writes := backend.snapshot()
		configure(t, retiredHome, "")

		h.writeProject(t, project, currentHome, true, retired, current)
		h.projectSnapshot(t, project) // Key expiry alone still allows historical reads.
		log := h.startTrace(t)
		if output, err := h.runTofu(t, project, "apply", "-replace=terraform_data.gpg_rewrite", "-auto-approve", "-input=false", "-no-color"); err == nil || !strings.Contains(strings.Join(strings.Fields(output), " "), "key "+retired+" has expired") {
			t.Fatalf("the normal removal rewrite accepted an expired recipient: err=%v\n%s", err, output)
		}
		if operations := traceOperations(t, log); operations["sign"] != 0 || operations["encrypt"] != 0 {
			t.Fatalf("an expired remote recipient was detected after signing: %v", operations)
		}
		unchanged, currentWrites := backend.snapshot()
		if currentWrites != writes || !bytes.Equal(original, unchanged) {
			t.Fatal("a rejected write modified remote state")
		}

		h.writeProjectConfig(t, project, currentHome, true, []string{current}, []string{retired})
		h.unchangedRemoteApply(t, project, backend)
		h.projectSnapshot(t, project) // Inspect the recovered state before rewriting it.
		state = h.rewriteRemoteState(t, project, backend, state)
		stored, _ := backend.snapshot()
		h.method(t, "decrypt", currentHome, decodeStateEnvelope(t, stored).Payload, nil, "--authorized-key", current)
		h.reject(t, "decrypt", retiredHome, decodeStateEnvelope(t, stored).Payload, nil, "GPG decryption failed", "--authorized-key", current)

		h.writeProject(t, project, currentHome, true, current)
		h.unchangedRemoteApply(t, project, backend)
		h.rewriteRemoteState(t, project, backend, state)
		h.tofuCommand(t, project, "state", "list")
		h.reject(t, "decrypt", currentHome, decodeStateEnvelope(t, original).Payload, nil, "signature from key "+retired+" is not authorized", "--authorized-key", current)
		h.method(t, "decrypt", currentHome, decodeStateEnvelope(t, original).Payload, nil, "--authorized-key", current, "--retired-key", retired)
	})
}

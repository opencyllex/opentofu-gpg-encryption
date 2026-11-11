package main_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCancellationWhileWaitingForStdin(t *testing.T) {
	name := "opentofu-gpg-key-provider"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, output)
	}
	for _, test := range []struct {
		name       string
		args       []string
		interrupt  bool
		diagnostic string
	}{
		{name: "timeout", args: []string{"--timeout", "100ms"}, diagnostic: context.DeadlineExceeded.Error()},
		{name: "interrupt", interrupt: true, diagnostic: context.Canceled.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.interrupt && runtime.GOOS == "windows" {
				t.Skip("os.Process.Signal does not support os.Interrupt on Windows")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, test.args...)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cancel()
					cmd.Wait()
				}
			}()
			reader := bufio.NewReader(stdout)
			header, err := reader.ReadString('\n')
			if err != nil || header != "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n" {
				t.Fatalf("protocol header = %q, error = %v", header, err)
			}
			if test.interrupt {
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					t.Fatal(err)
				}
			}
			body, readErr := io.ReadAll(reader)
			err = cmd.Wait()
			if ctx.Err() != nil {
				t.Fatal("provider did not exit while stdin remained open")
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), test.diagnostic) {
				t.Fatalf("error = %v, stderr = %q", err, &stderr)
			}
			if len(body) != 0 {
				t.Fatalf("failed request emitted a response: %q", body)
			}
		})
	}
}

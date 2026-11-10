package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Client invokes GnuPG with its normal configuration, keyring, and agent.
// A nil or empty Recipients slice leaves recipient selection to GnuPG.
type Client struct {
	Executable string
	HomeDir    string
	Recipients []string
}

// Encrypt wraps a data key for the configured GPG recipients.
func (c Client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	args := []string{"--no-armor", "--compress-algo", "none", "--set-filename", ""}
	for _, recipient := range c.Recipients {
		args = append(args, "--recipient", recipient)
	}
	args = append(args, "--encrypt", "--", "-")
	output, status, err := c.run(ctx, plaintext, args)
	if err != nil {
		if status.noRecipients {
			return nil, fmt.Errorf("no usable GPG recipient; supply --recipient or configure default-recipient/default-recipient-self in gpg.conf: %w", err)
		}
		return nil, fmt.Errorf("GPG encryption failed: %w", err)
	}
	if !status.encrypted || !status.authenticated {
		return nil, errors.New("GPG did not produce integrity-protected encrypted key material")
	}
	return output, nil
}

// Decrypt recovers a data key through gpg-agent and rejects unauthenticated or
// unencrypted input, even if GPG successfully extracts a literal data packet.
func (c Client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	output, status, err := c.run(ctx, ciphertext, []string{"--max-output", "32", "--decrypt", "--", "-"})
	if err != nil {
		clear(output)
		return nil, fmt.Errorf("GPG decryption failed: %w", err)
	}
	if !status.privateKey || !status.decrypted || !status.authenticated || status.integrityFailed {
		clear(output)
		return nil, errors.New("GPG did not confirm integrity-protected public-key decryption")
	}
	return output, nil
}

func (c Client) run(ctx context.Context, input []byte, operation []string) ([]byte, operationStatus, error) {
	// GPG reads gpg.conf itself. Command-line settings keep its data on pipes
	// and its prompts in pinentry, while preserving configured recipients.
	args := []string{
		"--batch", "--no-tty", "--no-verbose", "--debug-level", "none",
		"--pinentry-mode", "default",
		"--status-fd", "2", "--logger-fd", "2", "--output", "-",
	}
	if c.HomeDir != "" {
		args = append(args, "--homedir", c.HomeDir)
	}
	args = append(args, operation...)
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Bound waits for inherited pipes if a GPG helper outlives cancellation.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	status := readStatus(stderr.String())
	if ctx.Err() != nil {
		clear(stdout.Bytes())
		return nil, status, ctx.Err()
	}
	if err != nil {
		clear(stdout.Bytes())
		if status.diagnostics != "" {
			err = fmt.Errorf("%w: %s", err, status.diagnostics)
		}
		return nil, status, err
	}
	return stdout.Bytes(), status, nil
}

type operationStatus struct {
	encrypted       bool
	privateKey      bool
	decrypted       bool
	authenticated   bool
	integrityFailed bool
	noRecipients    bool
	diagnostics     string
}

func readStatus(stderr string) operationStatus {
	var status operationStatus
	var diagnostics []string
	var sessionKeyShown bool
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSuffix(line, "\r")
		message, machine := strings.CutPrefix(line, "[GNUPG:] ")
		if !machine {
			if line != "" {
				diagnostics = append(diagnostics, line)
			}
			continue
		}
		fields := strings.Fields(message)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "BEGIN_ENCRYPTION", "DECRYPTION_INFO":
			// These records contain MDC method, cipher, and optionally AEAD
			// algorithm. Either MDC or AEAD must protect the wrapped key.
			status.authenticated = len(fields) >= 3 && (fields[1] != "0" || (len(fields) >= 4 && fields[3] != "0"))
		case "END_ENCRYPTION":
			status.encrypted = true
		case "DECRYPTION_KEY":
			status.privateKey = true
		case "DECRYPTION_OKAY":
			status.decrypted = true
		case "BADMDC", "DECRYPTION_FAILED":
			status.integrityFailed = true
		case "NO_RECP", "INV_RECP":
			status.noRecipients = true
		case "SESSION_KEY":
			sessionKeyShown = true
		}
	}
	// A user's show-session-key setting also writes the session key to GPG's
	// human-readable log. Never forward that log, even on a failed request.
	if !sessionKeyShown {
		status.diagnostics = strings.Join(diagnostics, "\n")
	}
	return status
}

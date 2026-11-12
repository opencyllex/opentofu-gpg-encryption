package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Bind signatures to this protocol rather than arbitrary 32-byte files signed
// by the same GPG key for other purposes.
const keyPurpose = "OpenTofu-GPG-Key-Provider:data-key:v1\x00"

// Client invokes GnuPG with its normal configuration, keyring, and agent.
// Encrypt establishes authorized keys before Decrypt authenticates input.
type Client struct {
	Executable     string
	HomeDir        string
	AuthorizedKeys []string

	authorizedKeys []string
}

// Encrypt automatically selects the sole eligible signer, or uses GPG's signer
// selection when several are available. Every resulting signer must be authorized.
func (c *Client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	selected, err := c.selectSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("GPG signing failed: %w", err)
	}
	signArgs := []string{"--no-armor", "--no-textmode", "--compress-algo", "none", "--set-filename", ""}
	if selected != "" {
		signArgs = append(signArgs, "--local-user", selected)
	}
	signArgs = append(signArgs, "--sign", "--", "-")
	message := append([]byte(keyPurpose), plaintext...)
	defer clear(message)
	signed, status, err := c.run(ctx, message, signArgs)
	if err != nil {
		return nil, fmt.Errorf("GPG signing failed: %w", err)
	}
	defer clear(signed)
	if len(status.createdSigners) == 0 {
		return nil, errors.New("GPG did not create a binary signature")
	}
	var signers []string
	for _, fingerprint := range status.createdSigners {
		signer, err := c.primaryFingerprint(ctx, fingerprint)
		if err != nil {
			return nil, err
		}
		if len(c.AuthorizedKeys) != 0 && !slices.Contains(c.AuthorizedKeys, signer) {
			return nil, fmt.Errorf("GPG signing key %s is not authorized; add its primary fingerprint with --authorized-key or change default-key/local-user in gpg.conf; every configured local-user must be authorized", signer)
		}
		if !slices.Contains(signers, signer) {
			signers = append(signers, signer)
		}
	}
	authorized := c.AuthorizedKeys
	if len(authorized) == 0 {
		authorized = signers
	}

	// The input is already a signed OpenPGP packet stream. Do not put it in
	// another literal packet: decryption must also verify the inner signature.
	args := []string{"--no-armor", "--no-textmode", "--compress-algo", "none", "--no-literal", "--no-default-recipient", "--no-encrypt-to", "--no-groups"}
	for _, fingerprint := range authorized {
		args = append(args, "--recipient", fingerprint)
	}
	args = append(args, "--encrypt", "--", "-")
	output, status, err := c.run(ctx, signed, args)
	if err != nil {
		return nil, fmt.Errorf("GPG encryption failed: %w", err)
	}
	if !status.encrypted || !status.integrityProtected {
		return nil, errors.New("GPG did not produce integrity-protected encrypted key material")
	}
	c.authorizedKeys = authorized
	return output, nil
}

func (c *Client) selectSigner(ctx context.Context) (string, error) {
	listing, _, err := c.run(ctx, nil, []string{"--with-colons", "--with-fingerprint", "--with-secret", "--list-secret-keys"})
	if err != nil {
		return "", fmt.Errorf("list GPG signing keys: %w", err)
	}
	var candidates []string
	var primary string
	var usable, signingSecret bool
	collect := func() {
		if usable && signingSecret && (len(c.AuthorizedKeys) == 0 || slices.Contains(c.AuthorizedKeys, primary)) {
			candidates = append(candidates, primary)
		}
	}
	for line := range strings.SplitSeq(string(listing), "\n") {
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "sec":
			collect()
			primary, usable, signingSecret = "", false, false
			if len(fields) >= 15 {
				// Uppercase S describes usable signing capability across the
				// whole key; lowercase s describes this particular key packet.
				usable = strings.Contains(fields[11], "S") && !strings.Contains(fields[11], "D") && !strings.ContainsAny(fields[1], "ired")
				signingSecret = strings.Contains(fields[11], "s") && fields[14] != "" && fields[14] != "#"
			}
		case "ssb":
			if len(fields) >= 15 && !strings.ContainsAny(fields[1], "ired") && strings.Contains(fields[11], "s") && fields[14] != "" && fields[14] != "#" {
				signingSecret = true
			}
		case "fpr":
			if primary == "" && len(fields) >= 10 {
				primary = fields[9]
			}
		}
	}
	collect()
	switch len(candidates) {
	case 0:
		if len(c.AuthorizedKeys) != 0 {
			return "", errors.New("no authorized GPG key has a usable signing secret key")
		}
		return "", errors.New("no usable GPG signing secret key is available")
	case 1:
		return candidates[0], nil
	default:
		return "", nil
	}
}

// Decrypt requires integrity-protected public-key encryption and valid binary
// signatures exclusively from authorized primary keys or their signing subkeys.
func (c *Client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	output, status, err := c.run(ctx, ciphertext, []string{"--max-output", strconv.Itoa(len(keyPurpose) + 32), "--decrypt", "--", "-"})
	if err != nil {
		return nil, fmt.Errorf("GPG decryption failed: %w", err)
	}
	if !status.privateKey || !status.decrypted || !status.integrityProtected || !status.integrityVerified || status.integrityFailed {
		clear(output)
		return nil, errors.New("GPG did not confirm integrity-protected public-key decryption")
	}
	if status.plaintexts != 1 || status.signatureFailed || len(status.validSigners) == 0 {
		clear(output)
		return nil, errors.New("GPG did not confirm valid binary signatures from authorized keys")
	}
	for _, signer := range status.validSigners {
		if !slices.Contains(c.authorizedKeys, signer) {
			clear(output)
			return nil, fmt.Errorf("GPG signature from key %s is not authorized", signer)
		}
	}
	key, ok := bytes.CutPrefix(output, []byte(keyPurpose))
	if !ok {
		clear(output)
		return nil, errors.New("GPG-signed message is not tagged as an OpenTofu data key")
	}
	return key, nil
}

func (c *Client) primaryFingerprint(ctx context.Context, fingerprint string) (string, error) {
	listing, _, err := c.run(ctx, nil, []string{"--with-colons", "--with-fingerprint", "--list-keys", "--", fingerprint})
	if err != nil {
		return "", fmt.Errorf("identify GPG signing key: %w", err)
	}
	primary := false
	for line := range strings.SplitSeq(string(listing), "\n") {
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "pub":
			primary = true
		case "sub":
			primary = false
		case "fpr":
			if primary && len(fields) >= 10 {
				return fields[9], nil
			}
		}
	}
	return "", errors.New("GPG did not identify the signing key's primary fingerprint")
}

func (c Client) run(ctx context.Context, input []byte, operation []string) ([]byte, operationStatus, error) {
	// GPG reads gpg.conf itself. Command-line settings keep its data on pipes
	// and its prompts in pinentry.
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
	encrypted          bool
	privateKey         bool
	decrypted          bool
	integrityProtected bool
	integrityVerified  bool
	integrityFailed    bool
	createdSigners     []string
	validSigners       []string
	signatureFailed    bool
	plaintexts         int
	diagnostics        string
}

func readStatus(stderr string) operationStatus {
	var status operationStatus
	var diagnostics []string
	var sessionKeys []string
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
			status.integrityProtected = len(fields) >= 3 && (fields[1] != "0" || (len(fields) >= 4 && fields[3] != "0"))
		case "END_ENCRYPTION":
			status.encrypted = true
		case "DECRYPTION_KEY":
			status.privateKey = true
		case "DECRYPTION_OKAY":
			status.decrypted = true
		case "GOODMDC":
			// GPG also emits this status for successfully verified AEAD data.
			status.integrityVerified = true
		case "BADMDC", "DECRYPTION_FAILED":
			status.integrityFailed = true
		case "SIG_CREATED":
			if len(fields) >= 7 && fields[1] == "S" && fields[4] == "00" {
				status.createdSigners = append(status.createdSigners, fields[6])
			}
		case "VALIDSIG":
			// The final fingerprint identifies the primary key even when a
			// signing subkey made the signature. Only binary signatures bind
			// every byte; text signatures canonicalize line endings.
			if len(fields) >= 11 && fields[9] == "00" {
				status.validSigners = append(status.validSigners, fields[10])
			} else {
				status.signatureFailed = true
			}
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG":
			status.signatureFailed = true
		case "PLAINTEXT":
			status.plaintexts++
		case "SESSION_KEY":
			if len(fields) >= 2 {
				_, key, _ := strings.Cut(fields[1], ":")
				if key != "" {
					sessionKeys = append(sessionKeys, key)
				}
			}
		}
	}
	// A user's show-session-key setting also writes the session key to GPG's
	// human-readable log. Filter by key value so translated logs are safe too.
	for _, key := range sessionKeys {
		diagnostics = slices.DeleteFunc(diagnostics, func(line string) bool {
			return strings.Contains(line, key)
		})
	}
	status.diagnostics = strings.Join(diagnostics, "\n")
	return status
}

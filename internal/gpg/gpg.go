package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Bind signatures to OpenTofu payloads rather than other documents signed by
// the same GPG keys. The limit also bounds decompression of untrusted messages.
const (
	payloadPurpose = "OpenTofu-GPG-Encryption:payload:v1\x00"
	MaxPayloadSize = 256 * 1024 * 1024
)

// Client invokes GnuPG with its normal configuration, keyring, and agent.
type Client struct {
	Executable     string
	HomeDir        string
	AuthorizedKeys []string
	RetiredKeys    []string
}

// Encrypt requires a sole usable local identity when authorization is implicit.
// With explicit authorization it selects the sole eligible signer, or lets GPG
// select among several. Every resulting signer must be authorized.
func (c *Client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	keys, err := c.localKeys(ctx)
	if err != nil {
		return nil, err
	}
	selected, authorized, err := c.selectSigner(keys)
	if err != nil {
		return nil, err
	}
	if err := c.checkRecipients(ctx, authorized); err != nil {
		return nil, err
	}
	signArgs := []string{"--no-armor", "--no-textmode", "--compress-algo", "none", "--set-filename", "", "--no-ask-sig-expire", "--default-sig-expire", "0"}
	if selected != "" {
		signArgs = append(signArgs, "--local-user", selected)
	}
	signArgs = append(signArgs, "--sign", "--", "-")
	message := io.MultiReader(strings.NewReader(payloadPurpose), bytes.NewReader(plaintext))
	signed, status, err := c.run(ctx, message, signArgs, packetOutputSizeHint(len(payloadPurpose)+len(plaintext), len(keys)))
	if err != nil {
		return nil, fmt.Errorf("GPG signing failed: %w", err)
	}
	defer clear(signed)
	if len(status.createdSigners) == 0 {
		return nil, errors.New("GPG did not create a binary signature")
	}
	for _, fingerprint := range status.createdSigners {
		var signer string
		for _, key := range keys {
			if slices.Contains(key.fingerprints, fingerprint) {
				signer = key.fingerprint
				break
			}
		}
		if signer == "" {
			return nil, errors.New("GPG did not identify the signing key's primary fingerprint")
		}
		if !slices.Contains(authorized, signer) {
			return nil, fmt.Errorf("GPG signing key %s is not authorized; add its primary fingerprint with --authorized-key or change default-key/local-user in gpg.conf; every configured local-user must be authorized", signer)
		}
	}

	// The input is already a signed OpenPGP packet stream. Do not put it in
	// another literal packet: decryption must also verify the inner signature.
	args := []string{"--no-armor", "--no-textmode", "--compress-algo", "none", "--cipher-algo", "AES256", "--no-literal", "--no-default-recipient", "--no-encrypt-to", "--no-groups"}
	for _, fingerprint := range authorized {
		args = append(args, "--recipient", fingerprint)
	}
	args = append(args, "--encrypt", "--", "-")
	output, status, err := c.run(ctx, bytes.NewReader(signed), args, packetOutputSizeHint(len(signed), len(authorized)))
	if err != nil {
		return nil, fmt.Errorf("GPG encryption failed: %w", err)
	}
	if !status.encrypted || !status.integrityProtected {
		return nil, errors.New("GPG did not produce integrity-protected encrypted data")
	}
	if !status.aes256 {
		return nil, errors.New("GPG did not confirm AES-256 payload encryption")
	}
	return output, nil
}

func (c *Client) selectSigner(keys []localKey) (string, []string, error) {
	authorized := c.AuthorizedKeys
	if len(authorized) == 0 {
		if len(c.RetiredKeys) != 0 {
			return "", nil, errors.New("--retired-key only permits reads; list active members with --authorized-key to write")
		}
		fingerprint, err := implicitKey(keys)
		if err != nil {
			return "", nil, err
		}
		authorized = []string{fingerprint}
	}
	var candidates []string
	var expired string
	for _, key := range keys {
		if slices.Contains(authorized, key.fingerprint) {
			if key.canSign {
				candidates = append(candidates, key.fingerprint)
			}
			if key.expired || key.expiredSigning {
				expired = key.fingerprint
			}
		}
	}
	switch len(candidates) {
	case 0:
		if expired != "" {
			return "", nil, fmt.Errorf("GPG signing key %s has expired; renew it with gpg --quick-set-expire and share the updated public key with other writers, or move it to --retired-key", expired)
		}
		if len(c.AuthorizedKeys) != 0 {
			return "", nil, errors.New("no authorized GPG key has a usable signing secret key")
		}
		return "", nil, errors.New("no usable GPG signing secret key is available")
	case 1:
		return candidates[0], authorized, nil
	default:
		return "", authorized, nil
	}
}

// Check every recipient before signing, including members whose private keys
// are not local. Uppercase E reports usable encryption capability for the whole
// identity; an expired encryption subkey must not block a still-usable one.
func (c *Client) checkRecipients(ctx context.Context, authorized []string) error {
	args := append([]string{"--with-colons", "--with-fingerprint", "--list-options", "show-unusable-subkeys", "--list-keys"}, authorized...)
	listing, _, err := c.run(ctx, nil, args, 0)
	if err != nil {
		return fmt.Errorf("list GPG encryption keys: %w", err)
	}
	type recipient struct {
		fingerprint string
		canEncrypt  bool
		expired     bool
		revoked     bool
	}
	var keys []recipient
	for line := range strings.SplitSeq(string(listing), "\n") {
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "pub":
			if len(fields) >= 12 {
				keys = append(keys, recipient{
					canEncrypt: strings.Contains(fields[11], "E") && !strings.Contains(fields[11], "D") && !strings.ContainsAny(fields[1], "ird"),
					expired:    fields[1] == "e",
					revoked:    fields[1] == "r",
				})
			}
		case "sub":
			if len(keys) != 0 && len(fields) >= 12 && strings.Contains(fields[11], "e") {
				key := &keys[len(keys)-1]
				key.expired = key.expired || fields[1] == "e"
				key.revoked = key.revoked || fields[1] == "r"
			}
		case "fpr":
			if len(keys) != 0 && len(fields) >= 10 && keys[len(keys)-1].fingerprint == "" {
				keys[len(keys)-1].fingerprint = fields[9]
			}
		}
	}
	for _, fingerprint := range authorized {
		// Duplicate keyring entries can describe the same primary identity.
		var expired, revoked, canEncrypt bool
		for _, key := range keys {
			if key.fingerprint == fingerprint {
				canEncrypt = canEncrypt || key.canEncrypt
				expired = expired || key.expired
				revoked = revoked || key.revoked
			}
		}
		if canEncrypt {
			continue
		}
		switch {
		case revoked:
			return fmt.Errorf("GPG encryption key %s has been revoked; move it to --retired-key to read and rewrite existing state", fingerprint)
		case expired:
			return fmt.Errorf("GPG encryption key %s has expired; renew it and share the updated public key with other writers, or move it to --retired-key to read and rewrite existing state", fingerprint)
		default:
			return fmt.Errorf("GPG key %s has no usable encryption key", fingerprint)
		}
	}
	return nil
}

type localKey struct {
	fingerprint    string
	fingerprints   []string
	usable         bool
	canSign        bool
	expired        bool
	expiredSigning bool
}

func (c *Client) localKeys(ctx context.Context) ([]localKey, error) {
	listing, _, err := c.run(ctx, nil, []string{"--with-colons", "--with-fingerprint", "--with-subkey-fingerprint", "--with-secret", "--list-secret-keys"}, 0)
	if err != nil {
		return nil, fmt.Errorf("list local GPG keys: %w", err)
	}
	var keys []localKey
	var key localKey
	var signingCap, secret, signingSecret bool
	collect := func() {
		if !secret {
			return
		}
		key.canSign = key.usable && !key.expired && signingCap && signingSecret
		index := slices.IndexFunc(keys, func(existing localKey) bool { return existing.fingerprint == key.fingerprint })
		if index == -1 {
			keys = append(keys, key)
			return
		}
		existing := &keys[index]
		existing.usable = existing.usable || key.usable
		existing.canSign = existing.canSign || key.canSign
		existing.expired = existing.expired || key.expired
		existing.expiredSigning = existing.expiredSigning || key.expiredSigning
		for _, fingerprint := range key.fingerprints {
			if !slices.Contains(existing.fingerprints, fingerprint) {
				existing.fingerprints = append(existing.fingerprints, fingerprint)
			}
		}
	}
	for line := range strings.SplitSeq(string(listing), "\n") {
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "sec":
			collect()
			key = localKey{}
			signingCap, secret, signingSecret = false, false, false
			if len(fields) >= 15 {
				// Uppercase S describes usable signing capability across the
				// whole key; lowercase s describes this particular key packet.
				key.usable = !strings.Contains(fields[11], "D") && !strings.ContainsAny(fields[1], "ird")
				key.expired = fields[1] == "e"
				signingCap = strings.Contains(fields[11], "S")
				secret = fields[14] != "" && fields[14] != "#"
				signingSecret = strings.Contains(fields[11], "s") && secret
			}
		case "ssb":
			if len(fields) >= 15 && fields[14] != "" && fields[14] != "#" {
				secret = true
				if !strings.ContainsAny(fields[1], "ired") && strings.Contains(fields[11], "s") {
					signingSecret = true
				}
				if fields[1] == "e" && strings.Contains(fields[11], "s") {
					key.expiredSigning = true
				}
			}
		case "fpr":
			if len(fields) >= 10 {
				if key.fingerprint == "" {
					key.fingerprint = fields[9]
				}
				key.fingerprints = append(key.fingerprints, fields[9])
			}
		}
	}
	collect()
	return keys, nil
}

// Expiry does not change implicit authorization: an expired identity can still
// authenticate historical payloads, but cannot sign new ones.
func implicitKey(keys []localKey) (string, error) {
	var candidates []string
	for _, key := range keys {
		if key.usable {
			candidates = append(candidates, key.fingerprint)
		}
	}
	switch len(candidates) {
	case 0:
		return "", errors.New("no usable local GPG private key is available; import your private key or connect its hardware token")
	case 1:
		return candidates[0], nil
	default:
		return "", errors.New("multiple local GPG keys are available; use --authorized-key or a policy provider to specify authorized signers")
	}
}

// Decrypt requires integrity-protected public-key encryption and valid binary
// signatures exclusively from authorized primary keys or their signing subkeys.
// Retired keys may bypass revocation, but no other signature checks.
// Key expiry alone does not invalidate historical payloads.
func (c *Client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	authorized := c.AuthorizedKeys
	if len(authorized) == 0 && len(c.RetiredKeys) == 0 {
		keys, err := c.localKeys(ctx)
		if err != nil {
			return nil, err
		}
		fingerprint, err := implicitKey(keys)
		if err != nil {
			return nil, err
		}
		authorized = []string{fingerprint}
	}
	output, status, err := c.run(ctx, bytes.NewReader(ciphertext), []string{"--max-output", strconv.Itoa(len(payloadPurpose) + MaxPayloadSize), "--decrypt", "--", "-"}, min(len(ciphertext), len(payloadPurpose)+MaxPayloadSize))
	if err != nil {
		return nil, fmt.Errorf("GPG decryption failed: %w", err)
	}
	if !status.privateKey || !status.decrypted || !status.integrityProtected || !status.integrityVerified || status.integrityFailed {
		clear(output)
		return nil, errors.New("GPG did not confirm integrity-protected public-key decryption")
	}
	if !status.aes256 {
		clear(output)
		return nil, errors.New("GPG did not confirm AES-256 payload encryption")
	}
	if status.plaintexts != 1 || status.signatureFailed || len(status.validSignatures) == 0 {
		clear(output)
		return nil, errors.New("GPG did not confirm valid binary signatures from authorized keys")
	}
	for _, signature := range status.validSignatures {
		if !slices.Contains(authorized, signature.primaryKey) && !slices.Contains(c.RetiredKeys, signature.primaryKey) {
			clear(output)
			return nil, fmt.Errorf("GPG signature from key %s is not authorized", signature.primaryKey)
		}
	}
	if status.expiredSigner || status.revokedSigner {
		if err := c.checkSignerRevocations(ctx, status.validSignatures); err != nil {
			clear(output)
			return nil, err
		}
	}
	payload, ok := bytes.CutPrefix(output, []byte(payloadPurpose))
	if !ok {
		clear(output)
		return nil, errors.New("GPG-signed message is not tagged as an OpenTofu payload")
	}
	return payload, nil
}

func (c *Client) checkSignerRevocations(ctx context.Context, signatures []signature) error {
	// GPG can report EXPKEYSIG instead of REVKEYSIG for an expired, revoked
	// signing key. Its public-key listing still reports revocation, including
	// revocation of an individual signing subkey.
	args := []string{"--with-colons", "--with-fingerprint", "--with-subkey-fingerprint", "--list-keys"}
	for _, signature := range signatures {
		args = append(args, signature.primaryKey)
	}
	listing, _, err := c.run(ctx, nil, args, 0)
	if err != nil {
		return fmt.Errorf("check GPG signing key revocation: %w", err)
	}
	var revoked bool
	listed := make(map[string]bool)
	for line := range strings.SplitSeq(string(listing), "\n") {
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "pub", "sub":
			revoked = len(fields) >= 2 && fields[1] == "r"
		case "fpr":
			if len(fields) >= 10 {
				listed[fields[9]] = listed[fields[9]] || revoked
			}
		}
	}
	for _, signature := range signatures {
		for _, fingerprint := range []string{signature.primaryKey, signature.signingKey} {
			revoked, found := listed[fingerprint]
			if !found {
				return fmt.Errorf("GPG did not list signing key %s for revocation checks", fingerprint)
			}
			if revoked && !slices.Contains(c.RetiredKeys, signature.primaryKey) {
				detail := ""
				if fingerprint != signature.primaryKey {
					detail = fmt.Sprintf(" (signing subkey %s)", fingerprint)
				}
				return fmt.Errorf("GPG signing key %s has been revoked%s; move its primary fingerprint to --retired-key for recovery reads", signature.primaryKey, detail)
			}
		}
	}
	return nil
}

func (c Client) run(ctx context.Context, input io.Reader, operation []string, outputSize int) ([]byte, operationStatus, error) {
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
	cmd.Stdin = input
	var stdout outputBuffer
	stdout.buffer.Grow(outputSize)
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Bound waits for inherited pipes after GPG exits or the context is cancelled.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	status := readStatus(stderr.String())
	if ctx.Err() != nil {
		clear(stdout.buffer.Bytes())
		return nil, status, ctx.Err()
	}
	if err != nil {
		clear(stdout.buffer.Bytes())
		if status.diagnostics != "" {
			err = fmt.Errorf("%w: %s", err, status.diagnostics)
		}
		return nil, status, err
	}
	return stdout.buffer.Bytes(), status, nil
}

// GPG's partial packet framing can add one byte per 512 input bytes. Allow 4 KiB
// per key for ordinary signature and recipient packets; these are sizing hints,
// not limits on the packets GPG may produce.
func packetOutputSizeHint(inputSize, keyCount int) int {
	return inputSize + inputSize/512 + 4096*keyCount
}

// Reserve space for normal uncompressed payloads up front. Compressed input or
// extra OpenPGP packets can still require growth; clear each old allocation so
// clearing the final output does not leave earlier plaintext copies behind.
type outputBuffer struct {
	buffer bytes.Buffer
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	if b.buffer.Available() < len(p) {
		previous := b.buffer.Bytes()
		b.buffer.Grow(len(p))
		clear(previous)
	}
	return b.buffer.Write(p)
}

type operationStatus struct {
	encrypted          bool
	privateKey         bool
	decrypted          bool
	aes256             bool
	integrityProtected bool
	integrityVerified  bool
	integrityFailed    bool
	createdSigners     []string
	validSignatures    []signature
	signatureFailed    bool
	expiredSigner      bool
	revokedSigner      bool
	plaintexts         int
	diagnostics        string
}

type signature struct {
	primaryKey string
	signingKey string
}

func readStatus(stderr string) operationStatus {
	var status operationStatus
	var diagnostics []string
	var sessionKeys []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSuffix(line, "\r")
		message, machine := strings.CutPrefix(line, "[GNUPG:] ")
		if !machine {
			// GPG always logs a translated note about our intentional use of
			// --no-literal. Preserve errors naming incompatible options too.
			if strings.Contains(line, "--no-literal") && strings.Count(line, "--") == 1 {
				continue
			}
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
			// algorithm. Either MDC or AEAD must protect the payload.
			status.integrityProtected = len(fields) >= 3 && (fields[1] != "0" || (len(fields) >= 4 && fields[3] != "0"))
			status.aes256 = len(fields) >= 3 && fields[2] == "9"
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
				status.validSignatures = append(status.validSignatures, signature{primaryKey: fields[10], signingKey: fields[1]})
			} else {
				status.signatureFailed = true
			}
		case "BADSIG", "ERRSIG", "EXPSIG":
			status.signatureFailed = true
		case "REVKEYSIG", "KEYREVOKED":
			// Resolve revocation per primary identity after verifying every
			// signature, so an exception cannot exempt an unrelated co-signer.
			status.revokedSigner = true
		case "EXPKEYSIG":
			// Key expiry alone is allowed, subject to VALIDSIG, authorization,
			// and a separate revocation check on the public keys.
			status.expiredSigner = true
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

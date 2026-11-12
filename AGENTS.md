# Project

This is a standalone Go executable implementing OpenTofu's version 1 external
key-provider protocol. GnuPG protects freshly generated AES-256 data keys;
OpenTofu's built-in `aes_gcm` method encrypts state and saved plans.

Use Go 1.27 or newer. The application has no third-party Go dependencies.
Support Windows, Linux, and macOS, including amd64 and arm64 release builds.

## Layout

- `cmd/opentofu-gpg-key-provider`: thin executable entry point and build version.
- `internal/cli`: argument parsing, GPG operation timeout, exit codes, and
  diagnostics.
- `internal/provider`: protocol exchange, metadata, and data-key lifecycle.
- `internal/gpg`: direct GnuPG subprocess invocation and machine-status checks.
- `integration`: executable-level tests with real GPG and OpenTofu.
- `examples`: complete HCL configurations for default and explicit authorized keys.
- `.github/workflows`: three-OS tests and tag-triggered releases.
- `.goreleaser.yaml`: six build targets, archives, and checksums.

## Documentation

Keep `README.md` focused on end users: a sole user generating a key and encrypting
their state, and a small team authorizing each member's key for shared state in
an S3-compatible backend. Include practical installation, key exchange, and
plaintext-state migration instructions. Treat `gpg.conf` as advanced settings;
the quick start must work without editing it. Keep protocol, cryptographic
implementation, build, and release details in this file.

## Protocol and key lifecycle

- Write the newline-terminated `OpenTofu-External-Key-Provider` version 1 header
  before reading stdin. Runtime stdout is exclusively protocol JSON.
- Accept `null` for an encryption-only request and stored metadata for recovery.
  Output uses `keys`, with base64-encoded `encryption_key` and, when applicable,
  `decryption_key`.
- Generate a fresh 32-byte encryption key for every invocation. Recover the old
  decryption key from input metadata independently of the new encryption key.
- Output metadata must describe the new encryption key. The persisted format is
  `external_data: {version: 1, encrypted_key: <base64 GPG ciphertext>}`.
- Metadata is a compatibility boundary. Reject malformed or unsupported input;
  a format change requires an explicit compatibility/migration decision. Input
  metadata is limited to 1 MiB; recovered data keys must be exactly 32 bytes.
- Keep raw keys in memory and process pipes. Keep key material out of arguments,
  diagnostic messages, and temporary files.
- Keep key-provider names stable in stored configurations. Renames require
  OpenTofu's `encrypted_metadata_alias` or an explicit migration.

## Security model

OpenTofu handles AES-GCM encryption, nonces, and authentication of state and plan
contents. GPG authenticates and protects the data keys; a separate external
encryption method is unnecessary.

Encryption to a public key alone does not authenticate the writer: anyone with
that public key can wrap a data key they chose. Requiring an authorized signature
prevents a backend or saved-plan writer with only public keys from substituting
their own data key and forging AES-GCM-encrypted content. OpenTofu's
`enforced = true` requires encryption but does not establish the signer's identity.
Valid historical ciphertext can still be replayed; this scheme does not establish
freshness or bind data to one project.

## GnuPG behavior

- Invoke `gpg` directly with separate arguments through `exec.CommandContext`.
  Keep its output separate from the OpenTofu protocol stream.
- Let GPG resolve its home and read `gpg.conf`. The provider does not parse that
  configuration or invoke `gpgconf`. Override output redirection and text mode so
  binary data keys stay on process pipes and round-trip unchanged.
- Authorized keys are optional, repeatable full primary-key fingerprints. Each
  key can decrypt data keys and authenticate signatures on recovered data keys.
  Accept only 40 or 64 hexadecimal characters, without spaces, a `0x` prefix, or
  a `!` suffix. Reject names, email addresses, and short or long key IDs.
  Automatically select the sole authorized key with a usable signing secret key,
  including signing subkeys. If several are eligible, GPG configuration selects
  the signer (`default-key` or `local-user`, otherwise the first secret key).
  Multiple `local-user` entries may produce multiple signatures; every signer
  must be authorized. Preserve `gpg.conf`, including additive `local-user` entries.
  Selecting a sole eligible key overrides `default-key`, but does not remove
  configured `local-user` signers. With no eligible key, fail without returning
  encryption keys.
  Without explicit authorized keys, implicitly authorize every freshly selected
  signer; no-flags single-user mode must work without signer configuration.
  Ignore `default-recipient*` and `encrypt-to` settings; preserve GPG's trust model.
  Imported public keys must be usable under that trust model. End-user team
  instructions use verified fingerprints and `gpg --quick-lsign-key` to establish
  local key validity without changing GPG configuration.
  Every selected signing secret key is required on every invocation, including
  read-only OpenTofu commands. Recovery also requires a corresponding decryption
  private key and every original signer's public key and authorization.
- Sign each new data key before encryption. Resolve implicit authorization from
  the signature on the freshly generated key, independently of stored metadata,
  before recovering the previous key. Reject writes by unauthorized signers.
- The signed plaintext is `OpenTofu-GPG-Key-Provider:data-key:v1`, a NUL byte,
  then the 32-byte data key. Require this purpose tag on recovery so generic GPG
  signatures cannot be repurposed as data-key authorizations. Direct
  `gpg --decrypt` returns the complete tagged message, not just the raw key.
- Use `gpg-agent` and default pinentry for private-key operations. Agent and
  hardware-token policy belong to GnuPG. Passphrase inputs are outside the CLI's
  scope.
- Require successful integrity-protected public-key decryption, using GPG's
  machine-readable status as well as its exit code. Require positive integrity
  verification for both MDC and AEAD. GPG can successfully unpack an unencrypted
  literal packet, which must not be accepted as a wrapped key.
- Require at least one binary signature; every signature must be valid and every
  signer an authorized primary fingerprint (or its signing subkey). Reject
  unsigned, invalid, expired, revoked, and unrelated signatures, including an
  unauthorized co-signature alongside a valid authorized signature, even when
  GPG succeeds or signature verification is skipped in its configuration.
  Unsigned or untagged wrapped keys from earlier development versions are
  intentionally unsupported.
- Reject integrity failures even when `ignore-mdc-error` is configured. Suppress
  diagnostic output containing session keys when `show-session-key` is enabled.
- OpenTofu imposes a one-minute external-provider timeout in versions 1.12/1.13;
  the executable defaults to a 45-second budget.

## Key rotation and historical data

Keep old and new fingerprints authorized during a transition, with an old
decryption private key available. Rewrite state with a remaining or new signer
before removing the old fingerprint, then rewrite again to encrypt only for the
remaining authorized keys. If several eligible private keys are present, select
the new signer through `default-key` or `local-user`; remove additive `local-user`
entries for retired signers before rewriting.

Historical state, saved plans, and backups still require a decryption private key
that could read them, every original signer's public key, and authorization of
every signer. Removing a key affects new writes and accepted signatures; it does
not revoke access to historical ciphertext that key could already decrypt.

## Testing and verification

Test observable behavior at the protocol/CLI boundary. Prefer actual GPG and
OpenTofu round trips for interoperability and crypto-related changes over tests
of private parsing helpers. End-to-end tests have been run with OpenTofu 1.12.6;
CI tests the latest OpenTofu on Linux, macOS, and Windows.

```text
go test ./...
go vet -tags integration ./...
go test -tags integration -v ./...
gofmt -l cmd internal integration
tofu fmt -check -recursive examples
actionlint
goreleaser check
goreleaser build --snapshot --clean
```

Integration tests require `gpg`, `tofu`, and `gpgconf`, with `gpgconf` installed
alongside `gpg`.
`gpgconf` is a test-only cleanup tool for agents using disposable keyrings.
Always isolate keys, GPG configuration, and state in temporary directories.
On macOS, create GPG test homes directly under `/tmp` to keep Unix-domain socket
paths short.
Windows CI extracts the native GnuPG bundle under `RUNNER_TEMP`. Keep its pinned
URL and SHA-256 checksum in sync when updating the workflow.

## Source builds and releases

Install with Go 1.27 or newer:

```text
go install github.com/opencyllex/opentofu-gpg-key-provider/cmd/opentofu-gpg-key-provider@latest
```

From a source checkout:

```text
go build -trimpath ./cmd/opentofu-gpg-key-provider
```

Go adds the `.exe` suffix on Windows.

A `v*` tag runs the three-OS test matrix before GoReleaser creates a draft GitHub
release with archives and checksums for all six OS/architecture combinations.
Publish the draft from GitHub when it is ready. Release builds use Git history;
the release workflow must check out the full history.

`goreleaser check` requires a Git remote to infer the release repository.
Snapshot builds work in a new repository without commits or a configured remote.
To verify archives and checksums without publishing:

```text
goreleaser release --snapshot --clean --skip=publish
```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
`type(scope): description`, with an optional scope. Choose an appropriate type,
such as `feat`, `fix`, `docs`, `test`, `ci`, `build`, `refactor`, or `chore`.
Keep the description concise and imperative. Mark breaking changes with `!`
after the type/scope or a `BREAKING CHANGE:` footer.

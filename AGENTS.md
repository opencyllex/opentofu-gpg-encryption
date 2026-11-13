# Project

This is a standalone Go executable implementing OpenTofu's version 1 external
encryption-method protocol. GnuPG signs and encrypts complete state and saved-plan
payloads with AES-256 session keys. An optional external key provider transports
public authorization and GPG configuration; it performs no cryptographic work.

Use Go 1.27 or newer. The application has no third-party Go dependencies.
Support Windows, Linux, and macOS, including amd64 and arm64 release builds.

## Layout

- `cmd/opentofu-gpg-encryption`: thin executable entry point and build version.
- `internal/cli`: argument parsing, GPG operation timeout, exit codes, and
  diagnostics.
- `internal/method`: encryption-method protocol exchange and optional policy input.
- `internal/provider`: policy-only key-provider protocol and metadata marker.
- `internal/policy`: versioned public policy and full-fingerprint validation.
- `internal/protocol`: cancellable bounded reads and strict JSON decoding.
- `internal/gpg`: direct GnuPG subprocess invocation and machine-status checks.
- `integration`: executable-level tests with real GPG and OpenTofu.
- `examples/single-user` and `examples/team`: complete HCL configurations.
- `.github/workflows`: three-OS tests and tag-triggered releases.
- `.goreleaser.yaml`: six build targets, archives, and checksums.

## Documentation

Keep `README.md` focused on end users: a sole user generating a key and encrypting
their state, and a small team authorizing each member's key for shared state in
an S3-compatible backend. Include practical installation, key exchange, and
plaintext-state migration instructions. Treat `gpg.conf` as advanced settings;
the quick start must work without editing it. Keep protocol, cryptographic
implementation, build, and release details in this file.

## Protocols and payload lifecycle

- `encrypt` and `decrypt` implement the external encryption-method protocol.
  Write the newline-terminated `OpenTofu-External-Encryption-Method` version 1
  header before reading stdin. Input contains a base64 `payload` and an optional
  base64 `key`; output contains a base64 `payload`. Runtime stdout is exclusively
  protocol JSON.
- The optional method `key` is a versioned public policy, not AES key material.
  Version 2 contains `version`, `authorized_keys`, `retired_keys`, `gpg`,
  and `homedir`. Emit and accept only this format, including an empty retired-key
  list when unused. Earlier unshipped policy formats are intentionally unsupported;
  policies are never stored in state. Policy supplies the current key roles and
  GPG executable/home to both operations.
  With no policy input, use the command-line settings and normal GPG home.
  Reject method configuration flags when a policy key is present; only `--timeout`
  may be supplied on those method commands.
- `policy` implements the version 1 `OpenTofu-External-Key-Provider` protocol,
  also writing its header before reading stdin. Accept `null` or the stored
  marker `external_data: {policy_version: 1}`. This metadata marker remains at
  version 1 independently of the public policy format. Return the current policy
  in both `keys.encryption_key` and `keys.decryption_key`, even without metadata,
  so adding the provider to existing GPG-encrypted state preserves read access.
  Always derive policy from current trusted CLI/HCL configuration, never metadata.
  The provider must not invoke GPG, generate cryptographic keys, sign, or decrypt.
- Policy and metadata formats are compatibility boundaries. Reject malformed,
  duplicate, case-variant, unknown, or unsupported fields; format changes require
  an explicit compatibility/migration decision. Policy and provider input are
  limited to 1 MiB. Method JSON input is limited to 512 MiB and plaintext payloads
  to 256 MiB; bound GPG's decrypted output to the purpose tag plus that limit.
- GPG generates a fresh session key for each actual encryption. There is no
  encryption-key preparation during method initialization. A state read performs
  no signing, including implicit single-user authorization discovery. Hardware
  confirmations occur only for actual payload operations, not policy requests.
- Keep plaintext and key material in memory and process pipes, out of arguments,
  diagnostics, and temporary files. Public policy bytes are not secrets.
- The earlier development key-provider/AES-GCM format and executable name are
  intentionally unsupported by the new method. Migration uses the old executable
  and configuration to write plaintext, then OpenTofu's unencrypted fallback to
  rewrite it with the external GPG method. Recreate saved plans.
- Keep policy-provider names stable in stored configurations. Renames require
  OpenTofu's `encrypted_metadata_alias` or an explicit migration.

## Security model

The external method signs a purpose-tagged payload and encrypts the signed
OpenPGP packet stream with GPG. OpenTofu stores that ciphertext in its usual
encrypted envelope. The method requires GPG's integrity and signature status in
addition to a successful exit code before returning any plaintext.

Encryption to a public key alone does not authenticate the writer: anyone with
that public key can encrypt content they chose. Requiring authorized signatures
prevents a backend or saved-plan writer with only public keys from forging
accepted state or plan content. OpenTofu's
`enforced = true` requires encryption but does not establish the signer's identity.
Valid historical ciphertext can still be replayed; this scheme does not establish
freshness or bind data to one project.

## GnuPG behavior

- Invoke `gpg` directly with separate arguments through `exec.CommandContext`.
  Keep its output separate from the OpenTofu protocol stream.
- Let GPG resolve its home and read `gpg.conf`. The executable does not parse that
  configuration or invoke `gpgconf`. Override output redirection and text mode so
  binary payloads stay on process pipes and round-trip unchanged.
- Authorized keys are optional, repeatable full primary-key fingerprints. Each
  key can decrypt payloads and authenticate signatures on recovered payloads.
  Accept only 40 or 64 hexadecimal characters, without spaces, a `0x` prefix, or
  a `!` suffix. Reject names, email addresses, and short or long key IDs.
  Automatically select the sole authorized key with a usable signing secret key,
  including signing subkeys. If several are eligible, GPG configuration selects
  the signer (`default-key` or `local-user`, otherwise the first secret key).
  Multiple `local-user` entries may produce multiple signatures; every signer
  must be authorized. Preserve `gpg.conf`, including additive `local-user` entries.
  Selecting a sole eligible key overrides `default-key`, but does not remove
  configured `local-user` signers. With no eligible key, fail the write.
  Without `--authorized-key` or `--retired-key`, both operations implicitly authorize
  the sole local private-key identity that is not invalid, revoked, or disabled; expired
  identities still count. Require an explicit list when more than one is present
  and fail writes before signing. Merge duplicate keyring entries by primary
  fingerprint. Never sign a probe or trust identities selected by the ciphertext
  to discover authorization.
  No-flags single-user mode must work without signer configuration or a provider.
  Ignore `default-recipient*` and `encrypt-to` settings; preserve GPG's trust model.
  Imported public keys must be usable under that trust model. End-user team
  instructions use verified fingerprints and `gpg --quick-lsign-key` to establish
  local key validity without changing GPG configuration.
  Every selected signing secret key is required for writes. Reading requires a
  corresponding decryption private key and every original signer's public key
  and authorization, but does not require a signing private key.
- `--retired-key` is repeatable full-primary-fingerprint authorization for reads
  only, including historical signatures by expired keys and their signing subkeys.
  It also accepts otherwise-valid signatures despite revocation. Waive only
  revocation for these identities, never cryptographic validity,
  signature expiry, binary signature class, purpose tagging, or integrity checks.
  They are not active signing keys or new encryption recipients. Reject overlap
  with `--authorized-key`, including case variants. If either role is supplied,
  disable implicit authorization; a configuration with only retired keys must not write.
  Transport retired-key authorization only in the current trusted policy, never stored metadata.
- Before signing, require usable encryption capability (uppercase `E` in GPG's
  public-key listing) for every active authorized key. Diagnose expired primary
  keys and encryption subkeys by primary fingerprint, with renewal or retirement
  guidance. One unusable recipient blocks every member's writes. An expired
  encryption subkey must not block another usable encryption key for that identity.
- Sign actual payloads before encryption and reject every unauthorized signer.
  Encrypt signed OpenPGP packets with `--no-literal` to avoid adding a literal
  wrapper that would prevent decryption from verifying the inner signatures.
  Override compression, text mode, and signature expiry; payload signatures must
  not inherit `default-sig-expire`. Require AES-256 payload encryption and check
  the cipher reported by GPG on both encryption and decryption.
- The signed plaintext is `OpenTofu-GPG-Encryption:payload:v1`, a NUL byte, then
  the state or plan bytes. Require this tag so generic GPG signatures cannot be
  repurposed as OpenTofu payloads. Direct `gpg --decrypt` returns the full tagged
  message. Unsigned or untagged messages are unsupported.
- Use `gpg-agent` and default pinentry for private-key operations. Agent and
  hardware-token policy belong to GnuPG. Passphrase inputs are outside the CLI's
  scope.
- Require successful integrity-protected public-key decryption, using GPG's
  machine-readable status as well as its exit code. Require positive integrity
  verification for both MDC and AEAD. GPG can successfully unpack an unencrypted
  literal packet, which must not be accepted as encrypted data.
- Require at least one binary signature; every signature must be valid and every
  signer an authorized primary fingerprint (or its signing subkey). Reject
  unsigned payloads, invalid or expired signatures, revoked signing keys without
  an explicit recovery exception, and unrelated signatures, including an
  unauthorized co-signature alongside a valid authorized signature, even when
  GPG succeeds or signature verification is skipped in its configuration.
- Key expiry alone must not block historical reads. Accept `EXPKEYSIG` alongside
  cryptographically valid binary `VALIDSIG` records and the normal authorization
  and integrity checks, including implicit single-user authorization. GPG can emit
  `EXPKEYSIG` for expired, revoked keys too; check public-key listings for
  revocation of every primary key and actual signing subkey on these reads and
  on `REVKEYSIG`/`KEYREVOKED`. Resolve exceptions per primary identity; one allowed
  signer must not exempt another revoked co-signer.
  Expired signing keys cannot write. Diagnose them separately from missing
  private keys, naming the primary fingerprint. Revocation diagnostics also name
  the primary fingerprint needed by `--retired-key`, with subkeys as extra detail.
  Renewal and sharing updated public keys are needed for continued writes, not
  historical reads.
- Reject integrity failures even when `ignore-mdc-error` is configured. Suppress
  diagnostic output containing session keys when `show-session-key` is enabled.
- Pre-size GPG output buffers for ordinary uncompressed payloads, and clear old
  allocations if growth is needed for compressed input or additional packets.
  Omit GPG's translated informational `--no-literal` note from diagnostics while
  preserving errors about incompatible options.
- OpenTofu imposes a one-minute external-command timeout in versions 1.12/1.13;
  the executable defaults to a 45-second budget.

## Key rotation and historical data

Keep old and new fingerprints authorized during a transition, with an old
decryption private key available. Rewrite state with a remaining or new signer
before removing the old fingerprint, then rewrite again to encrypt only for the
remaining authorized keys. If several eligible private keys are present, select
the new signer through `default-key` or `local-user`; remove additive `local-user`
entries for retired signers before rewriting.

The team example includes an empty `terraform_data.gpg_rewrite` resource.
Use it for plaintext-state migration and every policy-change step:
`tofu apply -replace=terraform_data.gpg_rewrite` persists newly signed and encrypted
state; a no-change apply does not upload remote state. Review the complete plan
before approval: replacement also applies other pending changes. If a departing
key has expired or been revoked, move it to the read-only `--retired-key` list
instead of attempting the normal first rewrite.
Inspect and independently verify the recovered state, rewrite with a valid signer
and active recipients, remove the retired key, then repeat the replacement.
Historical copies keep their original signatures.

Historical state, saved plans, and backups still require a decryption private key
that could read them, every original signer's public key, and authorization of
every signer. Removing a key affects new writes and accepted signatures; it does
not revoke access to historical ciphertext that key could already decrypt.

## Testing and verification

Test observable behavior at the protocol/CLI boundary. Prefer actual GPG and
OpenTofu round trips for interoperability and crypto-related changes over tests
of private parsing helpers. End-to-end tests have been run with OpenTofu 1.12.6;
CI tests the latest OpenTofu on Linux, macOS, and Windows.

Use a small in-test HTTP server for remote-backend coverage, including locking,
unchanged ciphertext and no uploads on policy-only no-change applies, forced
rewrites for additions/removals, and the complete expired/revoked-key retirement cycle.
Check stored encryption, increasing serials, stable lineage and application data,
replacement IDs, signer authorization, and recipient access at the CLI boundary.

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
go install github.com/opencyllex/opentofu-gpg-encryption/cmd/opentofu-gpg-encryption@latest
```

From a source checkout:

```text
go build -trimpath ./cmd/opentofu-gpg-encryption
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

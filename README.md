# OpenTofu GPG Key Provider

A cross-platform Go executable implementing the [OpenTofu external key provider
protocol](https://opentofu.org/docs/language/state/encryption/#external-key-provider).
It uses **GnuPG (`gpg`) to sign and encrypt randomly generated AES-256 data keys**, and
OpenTofu's built-in **AES-GCM** method to encrypt state and saved plans.

Supports Linux, macOS, and Windows. Release builds target amd64 and arm64 on all
three systems. The implementation uses Go's standard library and an installed
copy of GnuPG, with normal keyring, agent, pinentry, and hardware-token support.

## Requirements and installation

- OpenTofu with the version 1 external key-provider protocol. End-to-end tests
  have been run with OpenTofu 1.12.6; CI tests the latest OpenTofu on all three OSes.
- GnuPG 2.2 or newer, with `gpg` on PATH, or an explicit `--gpg` executable path.
- Authorized public keys in the selected GPG keyring, with encryption and signing
  capabilities (possibly through separate subkeys). Every invocation needs an
  authorized signing private key through GPG's agent. Reading encrypted data also
  needs a corresponding decryption private key and the original signer's public key.

Install GnuPG for your platform:

- **Linux** (Debian/Ubuntu): `sudo apt-get install gnupg`.
- **macOS**: `brew install gnupg`.
- **Windows**: install [Gpg4win](https://gpg4win.org/).

Download a release archive for your OS and architecture, extract the executable,
and place it on PATH. Alternatively, install with Go 1.27 or newer:

```sh
go install github.com/opencyllex/opentofu-gpg-key-provider/cmd/opentofu-gpg-key-provider@latest
```

To build from a source checkout, use Go 1.27 or newer.
On Linux and macOS:

```sh
go build -trimpath -o opentofu-gpg-key-provider ./cmd/opentofu-gpg-key-provider
```

On Windows:

```powershell
go build -trimpath -o opentofu-gpg-key-provider.exe ./cmd/opentofu-gpg-key-provider
```

## Quick start: GPG's default key

Identify your full primary-key fingerprint using
`gpg --list-secret-keys --with-fingerprint`.
If several keys are available, select a default in your GnuPG home's `gpg.conf`:

```text
default-key YOUR_FULL_GPG_FINGERPRINT
```

For a single-user setup with one usable secret signing key, no `--authorized-key`
flag or `default-key` setting is needed. The provider automatically selects that
key and authorizes it for both reading and writing.

With several eligible signing keys, GPG uses `default-key`, or its first secret
key when no default is set. A `local-user` setting in `gpg.conf` overrides
`default-key`; repeated `local-user` settings select multiple signers. Without
`--authorized-key`, all keys that sign the freshly generated data key are
implicitly authorized. If no usable secret signing key is available, the request
fails. GPG's `default-recipient` and `default-recipient-self` settings are ignored.

GPG normally reads `~/.gnupg/gpg.conf` on Linux and macOS, or
`%APPDATA%\gnupg\gpg.conf` on Windows. `GNUPGHOME`, `--homedir`, and the Windows
GnuPG installation can change the location. The provider lets GPG resolve its
home and read its configuration; it does not parse `gpg.conf` or invoke
`gpgconf` at runtime.

For a **new project**, configure state and plan encryption:

```hcl
terraform {
  encryption {
    key_provider "external" "gpg" {
      command = ["opentofu-gpg-key-provider"]
    }

    method "aes_gcm" "gpg" {
      keys = key_provider.external.gpg
    }

    state {
      method   = method.aes_gcm.gpg
      enforced = true
    }

    plan {
      method   = method.aes_gcm.gpg
      enforced = true
    }
  }
}
```

Run OpenTofu normally. No Terraform/OpenTofu plugin installation or
`required_providers` entry is needed for this executable. A complete example is
in [`examples/default-key`](examples/default-key).

## Explicit and multiple authorized keys

**Authorized keys can read and write the state.** Use repeated
`--authorized-key` arguments to specify their full primary-key fingerprints:

```hcl
key_provider "external" "gpg" {
  command = [
    "opentofu-gpg-key-provider",
    "--authorized-key", "FIRST_FULL_GPG_FINGERPRINT",
    "--authorized-key", "SECOND_FULL_GPG_FINGERPRINT",
  ]
}
```

Each listed key can recover the data key, and signatures from that key are
accepted when reading state and saved plans. Valid signing subkeys are accepted
through their primary key's fingerprint. Fingerprints must be 40 or 64 hexadecimal
characters, without spaces, a `0x` prefix, or a `!` suffix. Email addresses,
names, and short or long key IDs are rejected: matching a user ID does not prove
who signed.

The provider looks for authorized keys with usable signing secret keys, including
signing subkeys:

- If there is **one eligible key**, select it automatically, even if GPG's
  `default-key` names a different key. Public-key-only authorized keys do not make
  the choice ambiguous.
- If there are **several eligible keys**, let GPG choose using `local-user` or
  `default-key` in `gpg.conf`, or its first secret key. Every resulting signer's
  primary fingerprint must be authorized, or the write fails.
- If there is **no eligible key**, fail without returning encryption keys.

GPG always reads `gpg.conf`. Its `local-user` settings are additive, so **every
configured `local-user` must be included in the explicit authorized-key list**,
even when a sole eligible key is selected automatically. Multiple signatures are
supported when all signers are authorized. GPG must be able to use every selected
signing private key; readers need every signer's public key and authorization.

For example, `default-key K1` with only `--authorized-key K2` selects K2 if its
signing secret key is available. With `local-user K1` instead, K1 must also be
authorized. To sign with both K1 and K2, configure both as `local-user` entries
and authorize both primary fingerprints.

Explicit authorized keys replace implicit authorization of the selected signing
keys. The provider ignores `default-recipient`, `default-recipient-self`,
and `encrypt-to`, so those settings cannot add readers. GPG's trust settings are
preserved; imported public keys must be usable under your chosen GPG trust model.
The provider never asks for keys or passphrases on protocol stdin.

See [`examples/authorized-keys`](examples/authorized-keys) for a
configuration using the `gpg_authorized_keys` variable. Encryption variables must
be available during `tofu init`; supply values through a variable file or `TF_VAR_*`.

## Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `--authorized-key FPR` | Selected signing keys | Full primary-key fingerprint authorized to read and write; repeatable. |
| `--gpg PATH` | `gpg` | GnuPG executable, resolved through PATH unless a path is supplied. |
| `--homedir PATH` | GPG home resolution | Pass this home directory to GPG; takes precedence over `GNUPGHOME`. |
| `--timeout DURATION` | `45s` | Time budget for metadata input and GPG operations, for example `30s`. |
| `--help` | | Print usage and exit. |
| `--version` | | Print the build version and exit. |

GPG is started directly, with arguments passed individually. For example, on
Linux:

```hcl
command = [
  "/usr/local/bin/opentofu-gpg-key-provider",
  "--gpg", "/usr/bin/gpg",
  "--homedir", "/home/example/.gnupg",
]
```

Paths containing spaces remain single arguments. Paths are passed literally;
expand `~` yourself or use an absolute path when needed. For Windows HCL paths,
use forward slashes or escaped backslashes.

OpenTofu 1.12/1.13 imposes a one-minute timeout on an external key provider.
Increasing `--timeout` cannot increase OpenTofu's limit. Complete any pinentry or
hardware-token interaction within that time budget.

## Private keys and unattended runs

Private-key operations are delegated to GPG and `gpg-agent`. The agent controls
passphrase caching, pinentry, smartcard PINs, and hardware-token touch policies.
The provider does not accept passphrases through arguments, files, or environment
variables, and does not import or export private keys.

Every write needs the private keys of all selected authorized signers. The
external key-provider protocol also requests a fresh encryption key on reads, so
read-only OpenTofu commands need signing access too. A public-key-only keyring
cannot serve provider requests.

On Linux and macOS, terminal pinentry commonly needs `GPG_TTY` set in the shell
that launches OpenTofu:

```sh
export GPG_TTY=$(tty)
```

For headless CI, provision the required GPG keys and an agent that can already
perform the private-key operation. Agent authorization and unlocking happen
outside this executable. GPG's default pinentry mode is used; protocol stdin is
never reused for passphrases.

## Key lifecycle and metadata

Each invocation generates a new 32-byte key using Go's cryptographic random
source. GPG signs a provider-specific purpose tag followed by this key, then
encrypts the signed message for the authorized keys. Only versioned metadata and
the signed-and-encrypted GPG message are persisted alongside OpenTofu's encrypted
payload:

```json
{
  "external_data": {
    "version": 1,
    "encrypted_key": "base64-encoded signed-and-encrypted GPG message"
  }
}
```

The signed plaintext is the ASCII string
`OpenTofu-GPG-Key-Provider:data-key:v1`, a NUL byte, and the 32-byte data key.
Direct `gpg --decrypt` returns this complete tagged message. The signed tag is
required: it prevents a signature over a known 32-byte file from another use of
the same GPG key from being repurposed as an attacker-chosen data key.

When metadata is supplied, the old key is recovered for decryption and a fresh
key is generated for the next write. The returned metadata always corresponds
to the new encryption key. Metadata is limited to 1 MiB; recovered data keys must
be exactly 32 bytes.

The provider requires GPG's machine-readable confirmation of integrity-protected
public-key decryption and **at least one binary signature, with every signature
valid and every signer authorized**. An authorized signature does not excuse an
unauthorized co-signature. Unsigned messages, signatures from other keys, invalid
or expired signatures, revoked signing keys, unencrypted packets, damaged
ciphertext, and unsupported metadata are rejected. Unsigned or untagged wrapped
keys from earlier development versions are not supported.

Encryption to a public key alone does not authenticate the writer: anyone with
that public key can wrap a data key they chose. Requiring an authorized signature
prevents a backend or saved-plan writer with only public keys from substituting
their own data key and forging AES-GCM-encrypted content. OpenTofu's
`enforced = true` requires encryption but does not establish the signer's identity.
As with other encrypted storage, valid historical ciphertext can still be
replayed; this scheme does not establish freshness or bind data to one project.

Raw keys travel only in memory and the required process pipes; they are not
placed in arguments, logs, or temporary files by the provider. GPG's output is
captured separately from OpenTofu's protocol stream. GPG configuration that
redirects data output or enables text mode is overridden to keep keys on process
pipes and preserve their binary contents.

OpenTofu handles AES-GCM encryption, nonces, and authentication of state/plan
contents. GPG authenticates and protects the data keys, so a separate external
encryption method is unnecessary.

## Authorized-key rotation

1. Make the old and new public keys available and list **both** with
   `--authorized-key`. Keep an old decryption private key available, and keep the
   fingerprints of all existing signers authorized while reading existing data.
2. Select the new signing key with `default-key` or `local-user` in `gpg.conf`,
   with its private key available. Remove any `local-user` entries for signers
   being retired so they do not add signatures to the rewrite. Run `tofu apply`
   to rewrite the state with a fresh key signed by the new signer and encrypted
   for the overlapping key list.
3. Remove the old `--authorized-key` entry and run `tofu apply` again. This rewrite
   encrypts the next data key only for the remaining authorized keys. With a
   single remaining key, you can instead return to implicit authorization by
   removing all flags and keeping the new GPG default signing key.

Previously saved plans, older state versions, and backups still need an old
decryption private key, every original signer's public key, and authorization of
every signer. Restore the necessary authorization when accessing them. Removing
a key affects new writes and accepted signatures; it does not revoke access to
historical ciphertext that key could already decrypt. Keep the key-provider name
stable, or use OpenTofu's `encrypted_metadata_alias` when planning a rename.

## Migrating existing plaintext state

For an existing project, initially add an unencrypted fallback and leave
`enforced` disabled during the migration:

```hcl
method "unencrypted" "migration" {}

state {
  method = method.aes_gcm.gpg
  fallback {
    method = method.unencrypted.migration
  }
}
```

After an apply writes encrypted state, remove the fallback and migration method
and set `enforced = true`. Use the same procedure for plans if needed. See
[OpenTofu's migration documentation](https://opentofu.org/docs/language/state/encryption/#pre-existing-project)
for the complete configuration.

## Development and verification

```sh
go test ./...
go vet -tags integration ./...
go test -tags integration -v ./...
tofu fmt -check -recursive examples
actionlint
goreleaser check
goreleaser build --snapshot --clean
```

Integration tests require `gpg`, `tofu`, and `gpgconf`, with `gpgconf` installed
alongside `gpg`. `gpgconf` is used **only by tests** to stop agents belonging to
their temporary keyrings. Tests generate disposable keys and use temporary GPG
homes and OpenTofu projects, leaving your normal keyring untouched. On macOS,
test GPG homes are created directly under `/tmp` to keep agent socket paths short.
The tests verify the real executable handshake, no-flags single-user mode,
automatic sole-signer selection, GPG default signing keys, multiple authorized
keys and signatures, signing subkeys, rejection of unsigned,
unauthorized-signature, and unrelated-purpose forgeries (including matching email
addresses), expired/revoked signatures, binary-key preservation with text mode
configured, wrong/missing keys, damaged ciphertext, timeouts, and OpenTofu
state/saved-plan encryption, forged-envelope rejection with `enforced = true`,
and authorized-key rotation.

GitHub Actions runs these tests on Linux, macOS, and Windows. Windows CI downloads
and extracts a pinned native GnuPG bundle with SHA-256 verification. A `v*` tag
runs the same test matrix before GoReleaser creates a draft GitHub release with
archives and checksums for all six OS/architecture combinations. Publish the draft
from GitHub when it is ready. Release builds use Git history; the release workflow
checks out the full history. `goreleaser check` also needs a Git remote to infer
the release repository. Snapshot builds work before the first commit or remote
is configured.

## License

[Mozilla Public License 2.0](LICENSE.md).

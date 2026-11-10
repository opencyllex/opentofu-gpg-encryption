# OpenTofu GPG Key Provider

A cross-platform Go executable implementing the [OpenTofu external key provider
protocol](https://opentofu.org/docs/language/state/encryption/#external-key-provider).
It uses **GnuPG (`gpg`) to protect randomly generated AES-256 data keys**, and
OpenTofu's built-in **AES-GCM** method to encrypt state and saved plans.

Supports Linux, macOS, and Windows. Release builds target amd64 and arm64 on all
three systems. The implementation uses Go's standard library and an installed
copy of GnuPG, with normal keyring, agent, pinentry, and hardware-token support.

## Requirements and installation

- OpenTofu with the version 1 external key-provider protocol. End-to-end tests
  have been run with OpenTofu 1.12.6; CI tests the latest OpenTofu on all three OSes.
- GnuPG 2.2 or newer, with `gpg` on PATH, or an explicit `--gpg` executable path.
- Recipient public keys in the selected GPG keyring. Reading encrypted data also
  needs access to a corresponding private key through GPG's agent.

Install GnuPG for your platform:

- **Linux** (Debian/Ubuntu): `sudo apt-get install gnupg`.
- **macOS**: `brew install gnupg`.
- **Windows**: install [Gpg4win](https://gpg4win.org/).

Download a release archive for your OS and architecture, extract the executable,
and place it on PATH. Alternatively, build from source with Go 1.27 or newer.
On Linux and macOS:

```sh
go build -trimpath -o opentofu-gpg-key-provider ./cmd/opentofu-gpg-key-provider
```

On Windows:

```powershell
go build -trimpath -o opentofu-gpg-key-provider.exe ./cmd/opentofu-gpg-key-provider
```

## Quick start: GPG's default recipient

Identify your full key fingerprint using `gpg --list-keys --with-fingerprint`.
In your GnuPG home's `gpg.conf`, configure:

```text
default-recipient YOUR_FULL_GPG_FINGERPRINT
```

Or select your own default key:

```text
default-key YOUR_FULL_GPG_FINGERPRINT
default-recipient-self
```

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
in [`examples/default-recipient`](examples/default-recipient).

## Explicit and multiple recipients

Use repeated `--recipient` arguments to override GPG's default recipient:

```hcl
key_provider "external" "gpg" {
  command = [
    "opentofu-gpg-key-provider",
    "--recipient", "FIRST_FULL_GPG_FINGERPRINT",
    "--recipient", "SECOND_FULL_GPG_FINGERPRINT",
  ]
}
```

Any listed recipient can recover the data key. This is useful for team access
and a recovery key. Full fingerprints provide unambiguous key selection; GPG
handles recipient matching and key validity using its own configuration.

Explicit recipients override `default-recipient`/`default-recipient-self`.
Additional recipients configured with GPG's `encrypt-to` are still honored.
GPG's trust settings are preserved; imported public keys must be usable under
your chosen GPG trust model.

Without explicit recipients or a usable GPG default, the request fails in batch
mode with a recipient-configuration error. The provider never asks for a
recipient on stdin, which belongs to the OpenTofu protocol.

See [`examples/explicit-recipients`](examples/explicit-recipients) for a
configuration using a recipient variable. Encryption variables must be available
during `tofu init`; supply values through a variable file or `TF_VAR_*`.

## Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `--recipient VALUE` | GPG configuration | Recipient selector; repeatable. Full fingerprints are recommended. |
| `--gpg PATH` | `gpg` | GnuPG executable, resolved through PATH unless a path is supplied. |
| `--homedir PATH` | GPG home resolution | Pass this home directory to GPG; takes precedence over `GNUPGHOME`. |
| `--timeout DURATION` | `45s` | Combined time budget for GPG operations, for example `30s`. |
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
source. GPG encrypts this key for the current recipients. Only versioned metadata
and the GPG ciphertext are persisted alongside OpenTofu's encrypted payload:

```json
{
  "external_data": {
    "version": 1,
    "encrypted_key": "base64-encoded GPG ciphertext"
  }
}
```

When metadata is supplied, the old key is recovered for decryption and a fresh
key is generated for the next write. The returned metadata always corresponds
to the new encryption key. Metadata is limited to 1 MiB; recovered data keys must
be exactly 32 bytes.

The provider checks GPG's machine-readable status for successful,
integrity-protected public-key decryption. Literal unencrypted packets, damaged
ciphertext, and unsupported metadata are rejected. Raw keys travel only in
memory and the required process pipes; they are not placed in arguments, logs,
or temporary files by the provider. GPG's output is captured separately from
OpenTofu's protocol stream. GPG configuration that redirects data output or
enables text mode is overridden to keep keys on process pipes and preserve their
binary contents.

OpenTofu handles AES-GCM encryption, nonces, and authentication of state/plan
contents. GPG protects only the data keys, so a separate external encryption
method is unnecessary.

## Recipient rotation

1. Make the new public keys available and change `--recipient` arguments or
   GPG's configured default recipient.
2. Keep the old private key available while reading the current encrypted data.
3. Run `tofu apply` to rewrite the state with a fresh key protected for the new
   recipients.

Previously saved plans, older state versions, and backups still need their old
private keys. Removing a recipient affects new writes; it does not revoke access
to historical ciphertext they could already decrypt. Keep the key-provider name
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
The tests verify the real executable handshake, GPG defaults, multiple
recipients, binary-key preservation with text mode configured, wrong/missing
keys, damaged ciphertext, timeouts, and OpenTofu state/saved-plan encryption and
recipient rotation.

GitHub Actions runs these tests on Linux, macOS, and Windows. A `v*` tag runs the
same test matrix before GoReleaser publishes archives and checksums for all six
OS/architecture combinations. Release builds use Git history; the release
workflow checks out the full history. `goreleaser check` also needs a Git remote
to infer the release repository. Snapshot builds work before the first commit
or remote is configured.

## License

[Mozilla Public License 2.0](LICENSE.md).

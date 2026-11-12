# OpenTofu GPG Key Provider

Encrypt your OpenTofu state and saved plans with your own GPG keys. Use one key
for a personal project, or let each member of a small team use their own key to
access shared state.

State is encrypted on your machine before it is stored locally or uploaded to a
backend. This also works with S3-compatible storage that has no server-side
encryption support.

- [Quick start: your own key](#quick-start-your-own-key)
- [Small team: shared state in S3](#small-team-shared-state-in-s3)
- [Encrypting existing state](#encrypting-existing-state)

## Quick start: your own key

### 1. Install the tools

Install [OpenTofu](https://opentofu.org/docs/intro/install/) and GnuPG 2.2 or newer:

- **Linux** (Debian/Ubuntu): `sudo apt-get install gnupg`.
- **macOS**: `brew install gnupg`.
- **Windows**: install [Gpg4win](https://gpg4win.org/).

Download the provider from [GitHub Releases](https://github.com/opencyllex/opentofu-gpg-key-provider/releases).
Choose the archive for your operating system and architecture, extract it, and
place `opentofu-gpg-key-provider` (`opentofu-gpg-key-provider.exe` on Windows) in a
directory on your `PATH`. Releases support Linux, macOS, and Windows on amd64 and
arm64.

Check that both tools are available in the terminal where you run OpenTofu:

```sh
gpg --version
opentofu-gpg-key-provider --version
```

### 2. Create your GPG key

If you already have a GPG key that supports signing and encryption, you can reuse
it. Otherwise, run:

```sh
gpg --generate-key
```

Follow the prompts for your name, email address, and passphrase. GPG creates a
key suitable for this provider using its default settings.

With just one private key, the provider selects it automatically. If you have
several, [choose one explicitly](#choosing-a-key-when-you-have-several). Keep a
secure backup of your private key and passphrase so you can recover your encrypted
state if you replace or lose your computer.

### 3. Enable encryption in your project

For a **new project**, create `encryption.tf` with the following contents. If your
project already has a state file, use the same configuration together with the
[migration steps below](#encrypting-existing-state) before running OpenTofu.

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

OpenTofu runs the executable directly; you do not need a `required_providers`
entry for it. A complete example is in [`examples/default-key`](examples/default-key).

### 4. Run OpenTofu

```sh
tofu init
tofu apply
```

Enter your GPG passphrase when prompted. Continue using OpenTofu as usual: state
is now stored encrypted, and saved plans created with `tofu plan -out=tfplan`
are encrypted too.

## Small team: shared state in S3

Each team member keeps their own private key and passphrase. Everyone uses the
same list of authorized public keys, and **each listed key can read and write
the shared state**.

Keep your existing S3 or S3-compatible backend configuration. OpenTofu encrypts
the state before uploading it, so this setup does not require encryption support
or a key-management service from your storage provider.

### 1. Create and exchange public keys

Each member follows steps 1 and 2 of the quick start to install the tools and
create their own key. Then list your keys:

```sh
gpg --list-keys --with-fingerprint
```

Copy your full **primary-key fingerprint**, shown below the `pub` line, removing
any spaces. Use this fingerprint in place of the placeholders below. An email
address or the shorter key ID will not work.

For example, Alice exports her public key and shares `alice-public.asc` with the
team:

```sh
gpg --armor --output alice-public.asc --export ALICE_FULL_FINGERPRINT
```

Bob does the same for his key. On Alice's computer, import Bob's public key:

```sh
gpg --import bob-public.asc
gpg --fingerprint BOB_FULL_FINGERPRINT
```

Compare the displayed fingerprint with the one Bob gives you in person or over a
call. Then mark the key as verified locally so GPG will use it for encryption:

```sh
gpg --quick-lsign-key BOB_FULL_FINGERPRINT
```

Bob repeats the import and verification for Alice's key. For a larger team,
everyone imports and verifies every other member's public key. Each person keeps
only their own private key.

### 2. Authorize every team member

Start with `encryption.tf` from the quick start and replace its `key_provider`
block with this one:

```hcl
key_provider "external" "gpg" {
  command = [
    "opentofu-gpg-key-provider",
    "--authorized-key", "ALICE_FULL_FINGERPRINT",
    "--authorized-key", "BOB_FULL_FINGERPRINT",
  ]
}
```

Add another `--authorized-key` pair for each additional member, including your
own key. Share this configuration with the team. On each computer, the provider
automatically selects that member's private key from the authorized list.

For new state, run `tofu init` and `tofu apply`. For existing shared state, follow
the migration below first. Afterwards, any authorized member with backend access
can use `tofu plan` and `tofu apply` with their own key.

See [`examples/authorized-keys`](examples/authorized-keys) for a complete example
that keeps the fingerprints in a `gpg_authorized_keys` variable. Supply its value
through a variable file or `TF_VAR_gpg_authorized_keys` so it is available during
`tofu init`.

## Encrypting existing state

For an existing local or remote state file, OpenTofu needs a temporary migration
setting to read the old, unencrypted state and write it encrypted.

Keep the `key_provider` and `aes_gcm` blocks from your chosen setup. Inside
`encryption`, temporarily replace the entire `state` block, including its
`enforced = true` setting, with the following method and state blocks:

```hcl
method "unencrypted" "migration" {}

state {
  method = method.aes_gcm.gpg
  fallback {
    method = method.unencrypted.migration
  }
}
```

Run `tofu init` and `tofu apply` to write encrypted state. Then remove the
`migration` method and restore the original `state` block with `enforced = true`.
This makes OpenTofu require encrypted state on subsequent runs.

Create new saved plans after enabling encryption. Older plaintext state versions
and backups remain unencrypted. See [OpenTofu's migration guide](https://opentofu.org/docs/language/state/encryption/#pre-existing-project)
for more migration options, including existing saved plans.

## Adding or removing team members

- **Add a member:** exchange and verify their public key on every computer, add
  their fingerprint to the shared authorized-key list, and have an existing
  member run `tofu apply`. The new member can read the state after that rewrite.
- **Remove a member:** first have a remaining member run `tofu apply` while the
  old fingerprint is still authorized. Then remove that fingerprint from the
  shared configuration and have the remaining member run `tofu apply` again.
  This order lets OpenTofu read the previous state and rewrite it for the
  remaining members.

Previously saved plans, older state versions, and backups still require a private
key that could read them and the public keys and authorization of their original
signers. Removing a member does not remove their access to old copies they could
already decrypt.

## Advanced settings

### Choosing a key when you have several

To use a particular key for a personal project, add one `--authorized-key` with
its full primary-key fingerprint to the command, using the same syntax as the
team example. The provider selects that key automatically.

### GPG configuration

The provider uses your usual GPG keyring and settings. If several authorized
private keys are available, GPG chooses which one signs using its configuration.
For example, you can select a default in `gpg.conf`:

```text
default-key YOUR_FULL_GPG_FINGERPRINT
```

GPG normally reads `~/.gnupg/gpg.conf` on Linux and macOS, or
`%APPDATA%\gnupg\gpg.conf` on Windows. A custom GPG home directory can change this
location.

If you already use `local-user` settings, they override `default-key`. Every
configured `local-user` must be authorized, and all selected private keys must be
available when OpenTofu runs. Use the authorized-key list to control who can
access the state; `default-recipient` and `encrypt-to` settings do not add readers.

### Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `--authorized-key FPR` | Selected signing keys | Full primary-key fingerprint authorized to read and write; repeatable. |
| `--gpg PATH` | `gpg` | GnuPG executable, resolved through PATH unless a path is supplied. |
| `--homedir PATH` | GPG's usual home | Use a different GPG home directory; takes precedence over `GNUPGHOME`. |
| `--timeout DURATION` | `45s` | Time limit for a provider request, for example `30s`. |
| `--help` | | Print usage and exit. |
| `--version` | | Print the build version and exit. |

Put each option and its value in separate elements of the `command` array. You
can use absolute executable paths if the tools are not on `PATH`. Paths containing
spaces stay in a single element; use forward slashes or escaped backslashes in
Windows HCL paths. The provider does not expand `~` in paths.

OpenTofu 1.12/1.13 imposes a one-minute timeout on an external key provider.
Increasing `--timeout` cannot increase OpenTofu's limit. Complete any passphrase
prompt or hardware-token confirmation within that time budget.

### Passphrase prompts and unattended runs

OpenTofu needs access to your signing private key even for commands that only
read state. GPG handles passphrase prompts, caching, and hardware-token access
through its agent.

On Linux and macOS, terminal pinentry commonly needs `GPG_TTY` set in the shell
that launches OpenTofu:

```sh
export GPG_TTY=$(tty)
```

For unattended CI, provision the required keys and an agent that can use them
before starting OpenTofu. The provider has no passphrase option; unlocking keys
is handled through GPG.

For source builds, implementation details, and contributor checks, see
[`AGENTS.md`](AGENTS.md).

## License

[Mozilla Public License 2.0](LICENSE.md).

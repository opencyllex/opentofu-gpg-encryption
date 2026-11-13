# OpenTofu GPG Encryption

Encrypt your OpenTofu state and saved plans with your own GPG keys. Use one key
for a personal project, or let each member of a small team use their own key to
access shared state.

State is encrypted on your machine before it is stored locally or uploaded to a
backend. This also works with S3-compatible storage that has no server-side
encryption support.

Signatures authenticate writers, but this setup does not detect rollback: someone
with backend write access can replace the current state with an older, validly
signed version.

- [Quick start: your own key](#quick-start-your-own-key)
- [Small team: shared state in S3](#small-team-shared-state-in-s3)
- [Encrypting existing state](#encrypting-existing-state)
- [Rewriting state after GPG policy changes](#rewriting-state-after-gpg-policy-changes)
- [Recovering state after a key expires or is revoked](#recovering-state-after-a-key-expires-or-is-revoked)

## Quick start: your own key

### 1. Install the tools

Install [OpenTofu](https://opentofu.org/docs/intro/install/) and GnuPG 2.2 or newer:

- **Linux** (Debian/Ubuntu): `sudo apt-get install gnupg`.
- **macOS**: `brew install gnupg`.
- **Windows**: install [Gpg4win](https://gpg4win.org/).

Download the executable from [GitHub Releases](https://github.com/opencyllex/opentofu-gpg-encryption/releases).
Choose the archive for your operating system and architecture, extract it, and
place `opentofu-gpg-encryption` (`opentofu-gpg-encryption.exe` on Windows) in a
directory on your `PATH`. Releases support Linux, macOS, and Windows on amd64 and
arm64.

Check that both tools are available in the terminal where you run OpenTofu:

```sh
gpg --version
opentofu-gpg-encryption --version
```

### 2. Create your GPG key

If you already have a GPG key that supports signing and encryption, you can reuse
it. Otherwise, run:

```sh
gpg --generate-key
```

Follow the prompts for your name, email address, and passphrase. GPG creates a
key suitable for this program using its default settings.

With just one private key, the program selects it automatically. If you have
several, [choose one explicitly](#choosing-a-key-when-you-have-several). Keep a
secure backup of your private key and passphrase so you can recover your encrypted
state if you replace or lose your computer.

GPG keys normally expire. Existing state remains readable after expiry, but new
writes require valid keys. [Renew expiring keys](#renewing-expiring-keys) to keep
writing with them.

### 3. Enable encryption in your project

For a **new project**, create `encryption.tf` with the following contents. If your
project already has a state file, use the same configuration together with the
[migration steps below](#encrypting-existing-state) before running OpenTofu.

```hcl
terraform {
  encryption {
    method "external" "gpg" {
      encrypt_command = ["opentofu-gpg-encryption", "encrypt"]
      decrypt_command = ["opentofu-gpg-encryption", "decrypt"]
    }

    state {
      method   = method.external.gpg
      enforced = true
    }

    plan {
      method   = method.external.gpg
      enforced = true
    }
  }
}
```

OpenTofu runs the executable directly; you do not need a `required_providers`
entry or a key-provider block for this single-user setup. GPG signs and encrypts
the actual state and plan data. A complete example is in
[`examples/single-user`](examples/single-user).

### 4. Run OpenTofu

```sh
tofu init
tofu apply
```

Enter your GPG passphrase when prompted. Continue using OpenTofu as usual: state
is now stored encrypted, and saved plans created with `tofu plan -out=tfplan`
are encrypted too.

Read-only commands such as `tofu state list` only decrypt and verify; they never
sign. Each state read needs one decryption (one confirmation on a hardware token).
Initialization requires no private-key operations.

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

Start with `encryption.tf` from the quick start. Inside `encryption`, add this
policy provider and replace the `method` block with the one below:

```hcl
key_provider "external" "gpg_policy" {
  command = [
    "opentofu-gpg-encryption", "policy",
    "--authorized-key", "ALICE_FULL_FINGERPRINT",
    "--authorized-key", "BOB_FULL_FINGERPRINT",
  ]
}

method "external" "gpg" {
  keys            = key_provider.external.gpg_policy
  encrypt_command = ["opentofu-gpg-encryption", "encrypt"]
  decrypt_command = ["opentofu-gpg-encryption", "decrypt"]
}
```

List one `--authorized-key` pair per member, including yourself. Share this
configuration with the team. On each computer, the program automatically selects
that member's signing private key from the authorized list.

The list is defined only once. The optional provider passes current public GPG
policy to both method commands; it does no signing or decryption and requires no
hardware-token confirmation. The `keys` argument carries this public policy,
not an AES key. Authorization always comes from the current configuration.

For new state, run `tofu init` and `tofu apply`. For existing unencrypted state,
follow the migration below first. A project already using this GPG method can
add the policy provider directly. When adding members to existing encrypted
state, have an existing member [force a state rewrite](#rewriting-state-after-gpg-policy-changes)
before the new members try to read it. Afterwards, any authorized member with
backend access can use `tofu plan` and `tofu apply` with their own key.

See [`examples/team`](examples/team) for a complete example that keeps the
fingerprints in a `gpg_authorized_keys` variable. Supply its value
through a variable file or `TF_VAR_gpg_authorized_keys` so it is available during
`tofu init`.

## Encrypting existing state

For an existing local or remote state file, OpenTofu needs a temporary migration
setting to read the old, unencrypted state and write it encrypted.

Keep the external method and optional policy-provider blocks from your chosen
setup. Inside `encryption`, temporarily replace the entire `state` block,
including its `enforced = true` setting, with the following method and state blocks:

```hcl
method "unencrypted" "migration" {}

state {
  method = method.external.gpg
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

The earlier development `opentofu-gpg-key-provider`/`aes_gcm` format is not read
by this method. Use the previous executable and configuration to
[migrate that state to plaintext](https://opentofu.org/docs/language/state/encryption/#rolling-back-encryption),
then follow the steps above to encrypt it in the new format. Recreate saved plans.

## Rewriting state after GPG policy changes

With S3 and other remote backends, membership changes take effect only after the
state changes and OpenTofu uploads a rewritten copy. A no-change `tofu apply`
does not re-encrypt remote state, even when the GPG policy has changed.

Keep this resource in your project; it is included in [`examples/team`](examples/team):

```hcl
resource "terraform_data" "gpg_rewrite" {}
```

It uses OpenTofu's built-in provider and manages no external infrastructure.
After changing the GPG policy, force a state update by replacing it:

```sh
tofu apply -replace=terraform_data.gpg_rewrite
```

Replacement changes the resource's ID, so OpenTofu uploads state signed and
encrypted using the current policy. Use this command at each rewrite step below
and wait for it to finish before proceeding. Run it in every affected workspace.
The command also applies any other pending changes. Review the complete plan
before approving each rewrite.

## Adding or removing team members

- **Add a member:** exchange and verify their public key on every computer, add
  their fingerprint to the shared authorized-key list, and have an existing
  member run `tofu apply -replace=terraform_data.gpg_rewrite`. The new member can
  read the state after that rewrite.
  The new member must also import and verify every existing member's public key
  so the program can check signatures on the shared state.
- **Remove a member:** if the departing member's key has expired or been revoked,
  use the recovery procedure below instead. Otherwise, first have a remaining
  member run
  `tofu apply -replace=terraform_data.gpg_rewrite` while the old fingerprint is
  still authorized. Then remove that fingerprint from the shared configuration
  and have the remaining member run
  `tofu apply -replace=terraform_data.gpg_rewrite` again. This order lets OpenTofu
  read the previous state and rewrite it for the remaining members.

Use a remaining member's signing key for both removal rewrites. If several
signing private keys are available, [select the remaining signer in GPG](#gpg-configuration)
and remove any `local-user` entries for the departing member before the first
rewrite.

Previously saved plans, older state versions, and backups still require a private
key that could read them and the public keys and authorization of their original
signers. Removing a member does not remove their access to old copies they could
already decrypt.

## Recovering state after a key expires or is revoked

To retire an expired or revoked member's key, use `--retired-key` as a temporary
read-only role. It accepts valid historical signatures from the named primary
key or its signing subkeys, including otherwise-valid signatures despite
revocation. The key is never selected to sign new writes or added as an encryption
recipient by this role. Integrity, signature validity, signature expiry, and every
co-signer's authorization are still checked.

1. Move the expired or revoked primary fingerprint from `--authorized-key` to
   `--retired-key`. Keep the remaining valid members under
   `--authorized-key`. For example:

   ```hcl
   command = [
     "opentofu-gpg-encryption", "policy",
     "--authorized-key", "ALICE_VALID_FINGERPRINT",
     "--authorized-key", "BOB_VALID_FINGERPRINT",
     "--retired-key", "RETIRED_MEMBER_FINGERPRINT",
   ]
   ```

   With [`examples/team`](examples/team), put the retired fingerprint in
   `gpg_retired_keys` and remove it from `gpg_authorized_keys`. A
   fingerprint cannot appear in both roles. An available recipient private key
   and every original signer's public key are still required for the read.
2. Read and inspect the state, and independently verify that it is correct before
   rewriting it. Then have a remaining valid member run the command below, reviewing
   the complete plan before approval. Any configured `local-user` entries must refer
   only to active authorized signers.

   ```sh
   tofu apply -replace=terraform_data.gpg_rewrite
   ```

   This reads with retired-key authorization and writes a fresh signature and
   ciphertext for the active authorized keys only.
3. Remove `--retired-key` (or clear `gpg_retired_keys`), then run:

   ```sh
   tofu apply -replace=terraform_data.gpg_rewrite
   tofu state list
   ```

   Normal reads now work without the retired-key authorization.

While configured, `--retired-key` accepts any otherwise-valid payload signed by
that identity, so trust in the particular state must come from the team's
independent verification. Recovery rewrites the current state only; older state
versions, backups, and saved plans retain their original signatures. Recreate
saved plans for future use.

## Renewing expiring keys

Existing state and saved plans remain readable after a key expires. A read still
needs a decryption private key and the public keys and authorization of every
original signer. You do not need to extend expiry or import renewed public keys
just to read historical data. The program creates signatures that do not expire.
Revoked keys are rejected unless explicitly allowed for
[recovery](#recovering-state-after-a-key-expires-or-is-revoked).

Expired keys cannot sign new state or plans, and GPG will not encrypt new payloads
to expired recipient keys. **One member's expired key blocks everyone's writes**
while that key remains authorized. To keep writing with the same authorized keys,
renew them and share their updated public keys with the other writers. The owner
can extend the primary key and its unexpired subkeys, for example by two years:

```sh
gpg --quick-set-expire YOUR_FULL_FINGERPRINT 2y
gpg --quick-set-expire YOUR_FULL_FINGERPRINT 2y "*"
gpg --armor --output updated-public.asc --export YOUR_FULL_FINGERPRINT
```

Share `updated-public.asc` with every writer, including CI machines,
and have them run `gpg --import updated-public.asc`. The fingerprint stays the
same, so the authorized-key list does not change. Keep the renewed private key
backup up to date too.

If a subkey has already expired, list its full fingerprint with
the following command:

```sh
gpg --list-keys --with-subkey-fingerprint --list-options show-unusable-subkeys
```

Replace `"*"` in the second renewal command with that subkey's fingerprint. Share
and import the updated public key in the same way so every member can keep writing.

Alternatively, to retire an already expired key, move it to the read-only
`--retired-key` role and follow the
[recovery rewrite procedure](#recovering-state-after-a-key-expires-or-is-revoked).

## Advanced settings

### Choosing a key when you have several

To use a particular key for a personal project, add one `--authorized-key` with
its full primary-key fingerprint to a policy-provider command, using the same
syntax as the team example. Both method commands then receive that selection.
You can also pass the same authorized-key options directly to both commands.

If several usable local private-key identities are available, both encryption and
decryption require an explicit authorized-key list. Expired identities still
count when selecting implicit authorization. The program never signs a probe or
uses the message's own signatures to decide which identities to trust.
If `--authorized-key` or `--retired-key` is supplied, authorization comes only from
the explicit lists. With `--retired-key`, list active writers and recipients with
`--authorized-key`; a configuration with only retired keys permits reads but no writes.

### GPG configuration

The program uses your usual GPG keyring and settings. If several authorized
signing private keys are available, GPG chooses which one signs using its
configuration.
For example, you can select a default in `gpg.conf`:

```text
default-key YOUR_FULL_GPG_FINGERPRINT
```

GPG normally reads `~/.gnupg/gpg.conf` on Linux and macOS, or
`%APPDATA%\gnupg\gpg.conf` on Windows. A custom GPG home directory can change this
location.

If you already use `local-user` settings, they override `default-key`. Every
configured `local-user` must be authorized, and all selected signing private keys
must be available when writing data. Reading requires a corresponding decryption
private key and every original signer's public key and authorization. Use the
authorized-key list to control who can access the state; `default-recipient` and
`encrypt-to` settings do not add readers.

### Command-line options

| Command | Purpose |
| --- | --- |
| `encrypt` | Sign and encrypt an actual state or plan payload. |
| `decrypt` | Decrypt a payload and require valid, authorized signatures. |
| `policy` | Pass public authorization and GPG settings through an optional external key provider. |

| Option | Default | Description |
| --- | --- | --- |
| `--authorized-key FPR` | Local key selection | Full primary-key fingerprint authorized to read and write; repeatable. |
| `--retired-key FPR` | None | Full primary-key fingerprint accepted for reads only, including otherwise-valid signatures despite revocation; never adds a writer or encryption recipient; repeatable. |
| `--gpg PATH` | `gpg` | GnuPG executable, resolved through PATH unless a path is supplied. |
| `--homedir PATH` | GPG's usual home | Use a different GPG home directory; takes precedence over `GNUPGHOME`. |
| `--timeout DURATION` | `45s` | Time limit for this command's request, for example `30s`. |
| `--help` | | Print usage and exit. |
| `--version` | | Print the build version and exit. |

Put the subcommand, each option, and its value in separate array elements. You
can use absolute executable paths if the tools are not on `PATH`. Paths containing
spaces stay in a single element; use forward slashes or escaped backslashes in
Windows HCL paths. The program does not expand `~` in paths.

The policy provider passes its `--authorized-key`, `--retired-key`, `--gpg`,
and `--homedir` settings to the method commands.
When `keys` is supplied to a method, put these settings on the policy-provider
command; the method rejects them rather than silently ignoring them. Only
`--timeout` may be set on those method commands to change their
cryptographic-operation budget.

OpenTofu 1.12/1.13 imposes a one-minute timeout on external encryption commands.
Increasing `--timeout` cannot increase OpenTofu's limit. Complete any passphrase
prompt or hardware-token confirmation within that time budget.

### Passphrase prompts and unattended runs

GPG handles passphrase prompts, caching, and hardware-token access through its
agent. Reading a payload requires one decryption operation and no signing
operations. Each actual write requires one signing operation per selected signer;
OpenTofu may write multiple state checkpoints during an apply. Policy-provider
requests and method initialization perform no private-key operations.

On Linux and macOS, terminal pinentry commonly needs `GPG_TTY` set in the shell
that launches OpenTofu:

```sh
export GPG_TTY=$(tty)
```

For unattended CI, provision the required keys and an agent that can use them
before starting OpenTofu. The program has no passphrase option; unlocking keys
is handled through GPG.

For source builds, implementation details, and contributor checks, see
[`AGENTS.md`](AGENTS.md).

## License

[Mozilla Public License 2.0](LICENSE.md).

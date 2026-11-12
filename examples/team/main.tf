variable "gpg_authorized_keys" {
  description = "Full GPG primary-key fingerprints authorized to read and write the state and saved plans."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.gpg_authorized_keys) > 0 && alltrue([
      for fingerprint in var.gpg_authorized_keys :
      can(regex("^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$", fingerprint))
    ])
    error_message = "Supply at least one full GPG primary-key fingerprint (40 or 64 hexadecimal characters)."
  }
}

terraform {
  encryption {
    key_provider "external" "gpg_policy" {
      command = concat(
        ["opentofu-gpg-encryption", "policy"],
        flatten([for fingerprint in var.gpg_authorized_keys : ["--authorized-key", fingerprint]])
      )
    }

    method "external" "gpg" {
      keys            = key_provider.external.gpg_policy
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

resource "terraform_data" "example" {
  input = "An example value protected for the configured authorized keys."
}

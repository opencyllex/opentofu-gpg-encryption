variable "gpg_authorized_keys" {
  description = "Full GPG primary-key fingerprints authorized to read and write the state and saved plans."
  type        = list(string)
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

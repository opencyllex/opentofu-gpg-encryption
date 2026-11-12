variable "gpg_authorized_keys" {
  description = "Full GPG primary-key fingerprints authorized to read and write the state and saved plans."
  type        = list(string)
}

terraform {
  encryption {
    key_provider "external" "gpg" {
      command = concat(
        ["opentofu-gpg-key-provider"],
        flatten([for fingerprint in var.gpg_authorized_keys : ["--authorized-key", fingerprint]])
      )
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

resource "terraform_data" "example" {
  input = "An example value protected for the configured authorized keys."
}

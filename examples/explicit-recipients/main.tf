variable "gpg_recipients" {
  description = "Full GPG fingerprints of the recipients allowed to decrypt the data keys."
  type        = list(string)
}

terraform {
  encryption {
    key_provider "external" "gpg" {
      command = concat(
        ["opentofu-gpg-key-provider"],
        flatten([for recipient in var.gpg_recipients : ["--recipient", recipient]])
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
  input = "An example value encrypted for the configured recipients."
}

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

resource "terraform_data" "example" {
  input = "An example value signed and encrypted using the sole local GPG key."
}

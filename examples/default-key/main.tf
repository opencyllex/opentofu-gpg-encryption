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

resource "terraform_data" "example" {
  input = "An example value protected using GPG's default signing key."
}

terraform {
  required_version = ">= 1.4, < 2.0"
}

# Built-in provider only. No AWS account, credentials or remote resources.
resource "terraform_data" "demo" {
  input = "local plan parser integration test"
}

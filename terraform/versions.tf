terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.60"
    }
  }

  # Remote state backend. Configure via `terraform init -backend-config=...`
  # using the files under environments/<env>/backend.hcl.
  # backend "s3" {}
}

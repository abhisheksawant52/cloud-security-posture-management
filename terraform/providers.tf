provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project     = "cloud-security-posture-management"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

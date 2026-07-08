locals {
  name = "${var.name_prefix}-${var.environment}"
}

data "aws_caller_identity" "current" {}

# Read-only security auditing role (SecurityAudit managed policy).
module "audit_role" {
  source = "./modules/audit-role"

  role_name              = "${local.name}-audit"
  trusted_principal_arns = var.trusted_principal_arns
  account_id             = data.aws_caller_identity.current.account_id
  tags = {
    Component = "audit-role"
  }
}

# S3 bucket that stores generated scan reports (SARIF/JSON).
resource "aws_s3_bucket" "reports" {
  bucket = var.reports_bucket_name
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-reports"
    status = "Enabled"

    filter {
      prefix = "reports/"
    }

    expiration {
      days = var.report_retention_days
    }
  }
}

# Optional EventBridge schedule that triggers periodic CSPM scans.
resource "aws_cloudwatch_event_rule" "scan_schedule" {
  count               = var.enable_schedule ? 1 : 0
  name                = "${local.name}-scan-schedule"
  description         = "Periodic trigger for CSPM benchmark scans"
  schedule_expression = var.scan_schedule_expression
}

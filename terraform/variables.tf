variable "aws_region" {
  description = "AWS region to deploy CSPM auditing resources into."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS profile used by the provider."
  type        = string
  default     = "default"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev or prod)."
  type        = string
  default     = "dev"
}

variable "name_prefix" {
  description = "Prefix applied to created resource names."
  type        = string
  default     = "cspm"
}

variable "trusted_principal_arns" {
  description = "IAM principal ARNs allowed to assume the read-only audit role."
  type        = list(string)
  default     = []
}

variable "reports_bucket_name" {
  description = "Globally unique S3 bucket name for scan reports."
  type        = string
}

variable "report_retention_days" {
  description = "Number of days to retain scan reports before expiration."
  type        = number
  default     = 90
}

variable "enable_schedule" {
  description = "Whether to create an EventBridge schedule for periodic scans."
  type        = bool
  default     = true
}

variable "scan_schedule_expression" {
  description = "EventBridge schedule expression controlling scan frequency."
  type        = string
  default     = "rate(24 hours)"
}

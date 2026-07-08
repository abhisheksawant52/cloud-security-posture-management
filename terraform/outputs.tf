output "audit_role_arn" {
  description = "ARN of the read-only security auditing role."
  value       = module.audit_role.role_arn
}

output "reports_bucket_name" {
  description = "Name of the S3 bucket storing scan reports."
  value       = aws_s3_bucket.reports.bucket
}

output "reports_bucket_arn" {
  description = "ARN of the S3 bucket storing scan reports."
  value       = aws_s3_bucket.reports.arn
}

output "scan_schedule_rule" {
  description = "Name of the EventBridge scan schedule rule, if enabled."
  value       = try(aws_cloudwatch_event_rule.scan_schedule[0].name, null)
}

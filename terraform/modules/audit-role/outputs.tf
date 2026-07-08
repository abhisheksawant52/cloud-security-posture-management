output "role_arn" {
  description = "ARN of the created audit role."
  value       = aws_iam_role.audit.arn
}

output "role_name" {
  description = "Name of the created audit role."
  value       = aws_iam_role.audit.name
}

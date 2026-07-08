variable "role_name" {
  description = "Name of the IAM audit role to create."
  type        = string
}

variable "trusted_principal_arns" {
  description = "IAM principal ARNs allowed to assume the role."
  type        = list(string)
  default     = []
}

variable "account_id" {
  description = "AWS account id used for the fallback trust principal."
  type        = string
}

variable "tags" {
  description = "Additional tags applied to the role."
  type        = map(string)
  default     = {}
}

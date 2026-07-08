locals {
  # Fall back to the account root if no explicit principals are provided so the
  # trust policy is always valid.
  principals = length(var.trusted_principal_arns) > 0 ? var.trusted_principal_arns : ["arn:aws:iam::${var.account_id}:root"]
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = local.principals
    }
  }
}

resource "aws_iam_role" "audit" {
  name               = var.role_name
  description        = "Read-only role for CSPM security auditing"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = var.tags
}

# AWS-managed SecurityAudit policy grants broad read-only access for auditing.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# ViewOnlyAccess complements SecurityAudit with additional describe/list rights.
resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

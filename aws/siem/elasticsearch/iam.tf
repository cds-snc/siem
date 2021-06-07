###
# AWS IAM role - CDS SIEM admin role
###

data "aws_iam_policy_document" "cds_siem_admin_role_inline" {
  statement {
    sid = "1"

    actions = ["es:*"]

    resources = [
      "arn:aws:es:${var.region}:${var.account_id}:domain/cds-siem/*"
    ]
  }
}

data "aws_iam_policy_document" "cds_siem_admin_role_assume" {
  statement {
    sid = "1"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.caller_arn]
    }
  }
}

resource "aws_iam_role" "cds_siem_admin_role" {
  name               = "cds-siem-admin-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_admin_role_assume.json
  inline_policy {
    name   = "cds-siem-snapshot-role-inline"
    policy = data.aws_iam_policy_document.cds_siem_admin_role_inline.json
  }
}
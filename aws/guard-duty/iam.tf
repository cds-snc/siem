###
# AWS IAM role - CDS SIEM loader access to GuardDuty Bucket
###

data "aws_iam_policy_document" "cds_siem_guard_duty_access_inline" {
  statement {
    sid = "1"

    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.guard_duty_logs.arn]
  }

  statement {
    sid = "2"

    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.guard_duty_logs.arn}/*"]
  }

  statement {
    sid = "3"

    actions   = ["kms:decrypt"]
    resources = [aws_kms_key.cds_siem_guard_duty_key.arn]
  }
}

resource "aws_iam_policy" "cds_siem_rguard_duty_access_policy" {
  name   = "cds-siem-guard-duty-access-policy"
  policy = data.aws_iam_policy_document.cds_siem_guard_duty_access_inline.json
}


resource "aws_iam_role_policy_attachment" "cds_siem_replication_role" {
  role       = var.loader_function_role
  policy_arn = aws_iam_policy.cds_siem_rguard_duty_access_policy.arn
}

data "aws_iam_policy_document" "cds_siem_firehose_role_inline" {
  statement {
    sid = "1"

    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.security_hub_logs.arn]
  }

  statement {
    sid = "2"

    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.security_hub_logs.arn}/*"]
  }
}

data "aws_iam_policy_document" "cds_siem_firehose_service_principal" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cds_siem_firehose_role" {
  provider           = aws.security-hub
  name               = "cds-siem-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_firehose_service_principal.json
  inline_policy {
    name   = "cds-siem-firehose-role-inline"
    policy = data.aws_iam_policy_document.cds_siem_firehose_role_inline.json
  }
}

resource "aws_kinesis_firehose_delivery_stream" "cds_siem_securityhub_stream" {
  provider    = aws.security-hub
  name        = "cds-siem-securityhub-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.cds_siem_firehose_role.arn
    bucket_arn          = aws_s3_bucket.security_hub_logs.arn
    error_output_prefix = "AWSLogs/${var.account_id}/SecurityHub/${var.region}/error"
    prefix              = "AWSLogs/${var.account_id}/SecurityHub/${var.region}"
    compression_format  = "GZIP"
  }
}
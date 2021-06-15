data "aws_iam_policy_document" "cds_siem_guard_duty_logs_kms_inline" {
  statement {
    sid = "1"

    actions   = ["kms:GenerateDataKey"]
    resources = ["arn:aws:kms:${var.region}:${regex("[0-9]+", var.logs_destination_bucket_id)}:key/*"]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "2"

    actions   = ["kms:*"]
    resources = ["arn:aws:kms:${var.region}:${regex("[0-9]+", var.logs_destination_bucket_id)}:key/*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${regex("[0-9]+", var.logs_destination_bucket_id)}:root",
        var.caller_arn
      ]
    }
  }
}

resource "aws_kms_key" "cds_siem_guard_duty_key" {
  description             = "CDS SIEM GuardDuty KMS"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cds_siem_guard_duty_logs_kms_inline.json
}

resource "aws_kms_alias" "cds_siem_guard_duty_key" {
  name          = "alias/guardduty-key"
  target_key_id = aws_kms_key.cds_siem_guard_duty_key.key_id
}
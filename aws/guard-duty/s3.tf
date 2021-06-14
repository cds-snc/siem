###
# AWS S3 bucket - GuardDuty logs for SIEM
###

resource "aws_s3_bucket" "guard_duty_logs" {
  bucket = "cds-siem-${var.env}-${regex("[0-9]+", var.logs_destination_bucket_id)}-guard-duty"
  acl    = "private"

  replication_configuration {
    role = aws_iam_role.cds_siem_replication_role.arn

    rules {
      id       = "replication-rule"
      priority = 0
      status   = "Enabled"

      destination {
        access_control_translation {
          owner = "Destination"
        }
        account_id    = regex("[0-9]+", var.logs_destination_bucket_id)
        bucket        = var.logs_destination_bucket_arn
        storage_class = "STANDARD"
      }
    }
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    enabled = true

    expiration {
      days = 14
    }
  }
}

data "aws_iam_policy_document" "cds_siem_guard_duty_policy" {
  statement {
    sid = "1"

    actions   = ["s3:GetBucketLocation"]
    resources = [aws_s3_bucket.guard_duty_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "2"

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.guard_duty_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "cds_siem_guard_duty_policy" {
  bucket = aws_s3_bucket.guard_duty_logs.id
  policy = data.aws_iam_policy_document.cds_siem_guard_duty_policy.json
}

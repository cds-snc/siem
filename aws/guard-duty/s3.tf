###
# AWS S3 bucket - GuardDuty logs for SIEM
###

resource "aws_s3_bucket" "guard_duty_logs" {
  bucket = "cds-siem-${var.env}-${regex("[0-9]+", var.logs_destination_bucket_id)}-guard-duty"
  acl    = "private"

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


resource "aws_lambda_permission" "cds_siem_log_trigger" {
  statement_id  = "AllowExecutionFromGuardDutyS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = var.loader_function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.guard_duty_logs.arn
}

resource "aws_s3_bucket_notification" "cds_siem_log_trigger_notification" {
  bucket = aws_s3_bucket.guard_duty_logs.id

  lambda_function {
    lambda_function_arn = var.loader_function_arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "AWSLogs/"
  }

  lambda_function {
    lambda_function_arn = var.loader_function_arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "UserLogs/"
  }

  depends_on = [aws_lambda_permission.cds_siem_log_trigger]
}
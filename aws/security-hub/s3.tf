###
# AWS S3 bucket - SecurityHub logs for SIEM
###

resource "aws_s3_bucket" "security_hub_logs" {
  provider = aws.security-hub
  bucket   = "cds-siem-${var.env}-${var.account_id}-security-hub"
  acl      = "private"

  replication_configuration {
    role = aws_iam_role.cds_siem_replication_role.arn

    rules {
      id       = "replication-rule"
      priority = 0
      status   = "Enabled"

      destination {
        bucket        = var.logs_destination_bucket_arn
        storage_class = "STANDARD"
      }
    }
  }

  versioning {
    enabled = true
  }
}
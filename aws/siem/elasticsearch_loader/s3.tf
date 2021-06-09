###
# AWS S3 bucket - ElasticSearch Logs
###

resource "aws_s3_bucket" "cds_siem_logs" {
  bucket = "cds-siem-${var.env}-${var.account_id}-logs"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true

    expiration {
      days = 90
    }
  }
}

###
# AWS S3 bucket - ElasticSearch Snapshots
###

resource "aws_s3_bucket" "cds_siem_snapshots" {
  bucket = "cds-siem-${var.env}-${var.account_id}-snapshots"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true

    expiration {
      days = 90
    }
  }
}
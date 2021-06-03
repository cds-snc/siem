###
# AWS S3 bucket - IP Geolocation data
###

resource "aws_s3_bucket" "ip_geolocation_data" {

  # Don't need to version these they should expire and are ephemeral
  # tfsec:ignore:AWS077

  bucket = "cds-siem-${var.env}-${var.account_id}-ip-geolocation"
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
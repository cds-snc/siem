data "aws_iam_policy_document" "cds_siem_logs_replication_policy" {
  statement {
    sid = "1"

    actions   = ["s3:GetBucketVersioning", "s3:PutBucketVersioning"]
    resources = [var.logs_destination_bucket_arn]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cds_siem_replication_role.arn]
    }
  }

  statement {
    sid = "2"

    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete"]
    resources = ["${var.logs_destination_bucket_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cds_siem_replication_role.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "cds_siem_logs_replication_policy" {
  bucket = var.logs_destination_bucket_id
  policy = data.aws_iam_policy_document.cds_siem_logs_replication_policy.json
}

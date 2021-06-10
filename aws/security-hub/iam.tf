###
# AWS IAM role - CDS SIEM replication role
###

data "aws_iam_policy_document" "cds_siem_replication_role_inline" {
  statement {
    sid = "1"

    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging"
    ]
    resources = ["${aws_s3_bucket.security_hub_logs.arn}/*"]
  }

  statement {
    sid = "2"

    actions = [
      "s3:ListBucket",
      "s3:GetReplicationConfiguration"
    ]
    resources = [aws_s3_bucket.security_hub_logs.arn]
  }

  statement {
    sid = "3"

    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags"
    ]
    resources = ["arn:aws:s3:::cds-siem-production-370045664819-logs/*"]
  }
}

data "aws_iam_policy_document" "cds_siem_replication_role_assume" {
  statement {
    sid = "1"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cds_siem_replication_role" {
  provider           = aws.security-hub
  name               = "cds-siem-replication-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_replication_role_assume.json
}

resource "aws_iam_policy" "cds_siem_replication_role" {
  provider = aws.security-hub
  name     = "cds-siem-replication-policy"
  policy   = data.aws_iam_policy_document.cds_siem_replication_role_inline.json
}

resource "aws_iam_role_policy_attachment" "cds_siem_replication_role" {
  provider   = aws.security-hub
  role       = aws_iam_role.cds_siem_replication_role.name
  policy_arn = aws_iam_policy.cds_siem_replication_role.arn
}

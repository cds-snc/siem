###
# AWS IAM role - CDS SIEM snapshot role
###

data "aws_iam_policy_document" "cds_siem_snapshot_role_inline" {
  statement {
    sid = "1"

    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.cds_siem_snapshots.arn]
  }

  statement {
    sid = "2"

    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.cds_siem_snapshots.arn}/*"]
  }
}

data "aws_iam_policy_document" "cds_siem_snapshot_role_assume" {
  statement {
    sid = "1"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cds_siem_snapshot_role" {
  name               = "cds-siem-snapshot-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_snapshot_role_assume.json
  inline_policy {
    name   = "cds-siem-snapshot-role-inline"
    policy = data.aws_iam_policy_document.cds_siem_snapshot_role_inline.json
  }
}

###
# AWS IAM role - CDS SIEM loader role
###

data "aws_iam_policy_document" "cds_siem_loader_role_inline" {
  statement {
    sid = "1"

    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::cds-siem-${var.env}-${var.account_id}-*"]
  }

  statement {
    sid = "2"

    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::cds-siem-${var.env}-${var.account_id}-*/*"]
  }

  statement {
    sid = "3"

    actions = ["es:*"]

    resources = [
      "arn:aws:es:${var.region}:${var.account_id}:domain/cds-siem/*"
    ]
  }

  statement {
    sid = "4"

    actions = ["sqs:SendMessage", "sqs:ReceiveMessage",
    "sqs:DeleteMessage", "sqs:GetQueueAttributes"]

    resources = [
      aws_sqs_queue.cds_siem_dead_letter_queue.arn,
      aws_sqs_queue.cds_siem_split_logs.arn
    ]
  }

  statement {
    sid = "5"

    actions   = ["kms:decrypt"]
    resources = ["arn:aws:kms:ca-central-1:${var.account_id}:key/*"]
  }
}

data "aws_iam_policy_document" "cds_siem_loader_role_assume" {
  statement {
    sid = "1"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy" "AWSLambdaBasicExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "cds_siem_loader_role" {
  name               = "cds-siem-loader-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_loader_role_assume.json
  inline_policy {
    name   = "cds-siem-loader-role-inline"
    policy = data.aws_iam_policy_document.cds_siem_loader_role_inline.json
  }
  managed_policy_arns = [data.aws_iam_policy.AWSLambdaBasicExecutionRole.arn]
}
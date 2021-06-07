resource "aws_cloudwatch_log_group" "cds_siem" {
  name              = "/aws/aes/domains/cds-siem/application-logs"
  retention_in_days = 14
}

data "aws_iam_policy_document" "cds_siem_cloudwatch_policy_document" {
  statement {
    sid = "1"

    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }

    actions = [
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
      "logs:CreateLogStream"
    ]

    resources = [
      "arn:aws:logs:*"
    ]
  }
}

resource "aws_cloudwatch_log_resource_policy" "cds_siem_cloudwatch_policy" {
  policy_name     = "cds-siem-cloudwatch-policy"
  policy_document = data.aws_iam_policy_document.cds_siem_cloudwatch_policy_document.json
}


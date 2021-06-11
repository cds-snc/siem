data "aws_iam_policy_document" "cds_siem_events_role_inline" {
  statement {
    sid = "1"

    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch"
    ]

    resources = [
      aws_kinesis_firehose_delivery_stream.cds_siem_securityhub_stream.arn
    ]
  }
}

data "aws_iam_policy_document" "cds_siem_events_service_principal" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cds_siem_events_role" {
  provider           = aws.security-hub
  name               = "cds-siem-events-role"
  assume_role_policy = data.aws_iam_policy_document.cds_siem_events_service_principal.json
  inline_policy {
    name   = "cds-siem-events-role-inline"
    policy = data.aws_iam_policy_document.cds_siem_events_role_inline.json
  }
}

resource "aws_cloudwatch_event_rule" "cds_siem_securityhub_rule" {
  provider    = aws.security-hub
  name        = "cds-siem-securityhub-rule"
  description = "Capture security hub events"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ]
}
PATTERN
}

resource "aws_cloudwatch_event_target" "cds_siem_securityhub_target" {
  provider  = aws.security-hub
  target_id = "cds-siem-securityhub-target"
  rule      = aws_cloudwatch_event_rule.cds_siem_securityhub_rule.name
  arn       = aws_kinesis_firehose_delivery_stream.cds_siem_securityhub_stream.arn
  role_arn  = aws_iam_role.cds_siem_events_role.arn
}
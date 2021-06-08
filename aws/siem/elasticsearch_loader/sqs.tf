resource "aws_sqs_queue" "cds_siem_dead_letter_queue" {
  name                      = "cds-siem-dead-letter-queue"
  message_retention_seconds = 1209600
  visibility_timeout_seconds = 900
}

resource "aws_sqs_queue" "cds_siem_split_logs" {
  name                      = "cds-siem-split_logs"
  message_retention_seconds = 1209600
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cds_siem_dead_letter_queue.arn
    maxReceiveCount     = 2
  })
  visibility_timeout_seconds = 900
}
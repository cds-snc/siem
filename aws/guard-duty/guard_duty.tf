data "aws_guardduty_detector" "guard_duty" {
  provider = aws.security-hub
}

resource "aws_guardduty_publishing_destination" "test" {
  provider        = aws.security-hub
  detector_id     = data.aws_guardduty_detector.guard_duty.id
  destination_arn = aws_s3_bucket.guard_duty_logs.arn
  kms_key_arn     = aws_kms_key.cds_siem_guard_duty_key.arn

  depends_on = [
    aws_s3_bucket_policy.cds_siem_guard_duty_policy,
  ]
}
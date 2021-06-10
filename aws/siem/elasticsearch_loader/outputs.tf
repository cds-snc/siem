output "logs_destination_bucket_arn" {
  value = aws_s3_bucket.cds_siem_logs.arn
}

output "logs_destination_bucket_id" {
  value = aws_s3_bucket.cds_siem_logs.id
}

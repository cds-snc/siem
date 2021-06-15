output "loader_function_arn" {
  value = aws_lambda_function.loader.arn
}

output "loader_function_name" {
  value = aws_lambda_function.loader.function_name
}

output "loader_function_role" {
  value = aws_iam_role.cds_siem_loader_role.name
}

output "logs_destination_bucket_arn" {
  value = aws_s3_bucket.cds_siem_logs.arn
}

output "logs_destination_bucket_id" {
  value = aws_s3_bucket.cds_siem_logs.id
}

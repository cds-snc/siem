output "ip_geolocation_bucket_arn" {
  value = aws_s3_bucket.ip_geolocation_data.arn
}

output "ip_geolocation_bucket" {
  value = aws_s3_bucket.ip_geolocation_data.bucket
}


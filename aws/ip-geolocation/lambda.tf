
resource "aws_lambda_function" "ip_geolocation" {
  function_name = "ip-geolocation"

  package_type = "Image"
  image_uri    = "${aws_ecr_repository.ip_geolocation.repository_url}:latest"

  timeout = 900

  memory_size = 512

  role = aws_iam_role.ip_geolocation.arn

  environment {
    variables = {
      MAXMIND_KEY    = var.maxmind_key
      S3_DESTINATION = aws_s3_bucket.ip_geolocation_data.bucket
    }
  }
}

resource "aws_cloudwatch_log_group" "ip_geolocation" {
  name              = "/aws/lambda/ip-geolocation"
  retention_in_days = 14
}
resource "aws_lambda_function" "ip_geolocation" {
  function_name = "ip-geolocation"

  package_type = "Image"
  image_uri    = "${aws_ecr_repository.ip_geolocation.repository_url}:e866937c313ff61f6868bb01b43d03781bda7240"

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

resource "aws_cloudwatch_event_rule" "once_a_day" {
  name                = "ip-geolocation-cron"
  description         = "Fires once a day"
  schedule_expression = "rate(24 hours)"
}

resource "aws_cloudwatch_event_target" "tigger_lambda_once_a_day" {
  rule      = aws_cloudwatch_event_rule.once_a_day.name
  target_id = aws_lambda_function.ip_geolocation.function_name
  arn       = aws_lambda_function.ip_geolocation.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ip_geolocation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.once_a_day.arn
}
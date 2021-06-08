resource "aws_lambda_function" "loader" {
  function_name = "loader"

  package_type = "Image"
  image_uri    = "${aws_ecr_repository.loader.repository_url}:18fd6ebde91d79586b730e72d882a49fc95080cd"

  timeout = 900

  memory_size = 2048

  role = aws_iam_role.cds_siem_loader_role.arn

  environment {
    variables = {
      ES_ENDPOINT                  = var.es_endpoint
      LOG_LEVEL                    = "info"
      GEOIP_BUCKET                 = var.ip_geolocation_bucket
      POWERTOOLS_LOGGER_LOG_EVENT  = "false",
      POWERTOOLS_SERVICE_NAME      = "es-loader",
      POWERTOOLS_METRICS_NAMESPACE = "SIEM"
      SQS_SPLITTED_LOGS_URL        = data.aws_sqs_queue.cds_siem_split_logs.url
    }
  }
}

resource "aws_lambda_event_source_mapping" "cds_siem_split_logs" {
  event_source_arn = aws_sqs_queue.cds_siem_split_logs.arn
  function_name    = aws_lambda_function.loader.arn
}

resource "aws_lambda_event_source_mapping" "cds_siem_dead_letter_queue" {
  event_source_arn = aws_sqs_queue.cds_siem_dead_letter_queue.arn
  function_name    = aws_lambda_function.loader.arn
}

resource "aws_lambda_permission" "cds_siem_log_trigger" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.loader.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.cds_siem_logs.arn
}

resource "aws_s3_bucket_notification" "cds_siem_log_trigger_notification" {
  bucket = aws_s3_bucket.cds_siem_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.loader.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "AWSLogs/"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.loader.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "UserLogs/"
  }

  depends_on = [aws_lambda_permission.cds_siem_log_trigger]
}
data "aws_iam_policy_document" "service_principal" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ip_geolocation" {
  name               = "siem-ip-geolocation"
  assume_role_policy = data.aws_iam_policy_document.service_principal.json
}

data "aws_iam_policy" "lambda_insights" {
  name = "CloudWatchLambdaInsightsExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "lambda_insights" {
  role       = aws_iam_role.ip_geolocation.name
  policy_arn = data.aws_iam_policy.lambda_insights.arn
}

data "aws_iam_policy_document" "ip_geolocation_policies" {

  statement {

    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "*"
    ]
  }

  statement {

    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]
    resources = [
      aws_s3_bucket.ip_geolocation_data.arn,
      "${aws_s3_bucket.ip_geolocation_data.arn}/*",
    ]

  }

  statement {

    effect = "Allow"

    actions = [
      "ecr:GetDownloadUrlForlayer",
      "ecr:BatchGetImage"
    ]
    resources = [
      aws_ecr_repository.ip_geolocation.arn
    ]
  }

}

resource "aws_iam_policy" "ip_geolocation" {
  name   = "siem-ip-geolocation"
  path   = "/"
  policy = data.aws_iam_policy_document.ip_geolocation_policies.json
}

resource "aws_iam_role_policy_attachment" "ip_geolocation" {
  role       = aws_iam_role.ip_geolocation.name
  policy_arn = aws_iam_policy.ip_geolocation.arn
}
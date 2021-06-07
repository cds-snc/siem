resource "aws_elasticsearch_domain" "cds_siem" {
  access_policies       = data.aws_iam_policy_document.cds_siem_access_policy.json
  domain_name           = "cds-siem"
  elasticsearch_version = "7.9"

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = aws_iam_role.cds_siem_admin_role.arn
    }
  }

  cluster_config {
    dedicated_master_enabled = false
    instance_count           = 1
    instance_type            = "t3.medium.elasticsearch"
    warm_enabled             = false
    zone_awareness_enabled   = false
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
    volume_type = "gp2"
  }

  encrypt_at_rest {
    enabled = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.cds_siem.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  node_to_node_encryption {
    enabled = true
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }
}

data "aws_iam_policy_document" "cds_siem_access_policy" {

  statement {
    sid = "1"

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions = [
      "es:*"
    ]

    resources = [
      "arn:aws:es:${var.region}:${var.account_id}:domain/cds-siem/*"
    ]
  }

  statement {
    sid = "2"

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "es:ESHttp*"
    ]

    resources = [
      "arn:aws:es:${var.region}:${var.account_id}:domain/cds-siem/*"
    ]

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"

      values = [
        "23.233.63.70/32",
      ]
    }
  }
}
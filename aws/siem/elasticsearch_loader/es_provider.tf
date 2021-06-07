terraform {
  required_providers {
    elasticsearch = {
      source  = "phillbaker/elasticsearch"
      version = "1.5.6"
    }
  }
}

provider "elasticsearch" {
  url                 = "https://${var.es_endpoint}"
  aws_assume_role_arn = var.cds_siem_admin_role_arn
}
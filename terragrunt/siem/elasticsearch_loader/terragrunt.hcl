terraform {
  source = "../../../aws/siem//elasticsearch_loader"
}

dependencies {
  paths = ["../elasticsearch", "../ip-geolocation"]
}

dependency "elasticsearch" {
  config_path = "../elasticsearch"
}

dependency "ip_geolocation" {
  config_path = "../ip-geolocation"
}

include {
  path = find_in_parent_folders()
}

inputs = {
  account_id = get_aws_account_id()
  cds_siem_admin_role_arn = dependency.elasticsearch.outputs.cds_siem_admin_role_arn
  es_endpoint = dependency.elasticsearch.outputs.es_endpoint
  ip_geolocation_bucket_arn = dependency.ip_geolocation.outputs.ip_geolocation_bucket_arn
}
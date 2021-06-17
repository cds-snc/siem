terraform {
  source = "../../../aws/siem//s3-replication"
}

dependencies {
  paths = ["../../cloud-trail", "../elasticsearch_loader", "../../security-hub"]
}

dependency "cloud_trail" {
  config_path = "../../cloud-trail"
}

dependency "elasticsearch_loader" {
  config_path = "../elasticsearch_loader"
}

dependency "security_hub" {
  config_path = "../../security-hub"
}

include {
  path = find_in_parent_folders()
}

inputs = {
  account_id = get_aws_account_id()
  logs_destination_bucket_arn = dependency.elasticsearch_loader.outputs.logs_destination_bucket_arn
  logs_destination_bucket_id = dependency.elasticsearch_loader.outputs.logs_destination_bucket_id
  cloud_trail_replication_role = dependency.cloud_trail.outputs.replication_role_arn
  security_hub_replication_role = dependency.security_hub.outputs.replication_role_arn
}
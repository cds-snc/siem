terraform {
  source = "../../aws//cloud-trail"
}

dependencies {
  paths = ["../siem/elasticsearch_loader"]
}

dependency "elasticsearch_loader" {
  config_path = "../siem/elasticsearch_loader"
}

include {
  path = find_in_parent_folders()
}

inputs = {
  account_id = get_env("LOGGING_ACCOUNT")
  logs_destination_bucket_arn = dependency.elasticsearch_loader.outputs.logs_destination_bucket_arn
  logs_destination_bucket_id = dependency.elasticsearch_loader.outputs.logs_destination_bucket_id
}
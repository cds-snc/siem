terraform {
  source = "../../aws//guard-duty"
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
  account_id = "400061975867"
  loader_function_arn = dependency.elasticsearch_loader.outputs.loader_function_arn
  loader_function_name = dependency.elasticsearch_loader.outputs.loader_function_name
  loader_function_role = dependency.elasticsearch_loader.outputs.loader_function_role
  logs_destination_bucket_arn = dependency.elasticsearch_loader.outputs.logs_destination_bucket_arn
  logs_destination_bucket_id = dependency.elasticsearch_loader.outputs.logs_destination_bucket_id
}
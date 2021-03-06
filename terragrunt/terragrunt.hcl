locals {
  env          = "production"
  logging_account = get_env("LOGGING_ACCOUNT")
  product_name = "cds-siem"
  security_account = get_env("SECURITY_ACCOUNT")
}

# DO NOT CHANGE ANYTHING BELOW HERE UNLESS YOU KNOW WHAT YOU ARE DOING

inputs = {
  caller_arn   = get_aws_caller_identity_arn()
  env          = local.env
  product_name = local.product_name
  region       = "ca-central-1"
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite"
  contents  = <<EOF
provider "aws" {
  region              = var.region
  allowed_account_ids = [${get_aws_account_id()}]
}

provider "aws" {
  alias               = "us-east-1"
  region              = "us-east-1"
  allowed_account_ids = [${get_aws_account_id()}]
}

provider "aws" {
  alias               = "security-hub"
  region              = "ca-central-1"
  allowed_account_ids = ["${local.security_account}"]
  assume_role {
    role_arn = "arn:aws:iam::${local.security_account}:role/cds-siem"
  }
}

provider "aws" {
  alias               = "cloud-trail"
  region              = "ca-central-1"
  allowed_account_ids = ["${local.logging_account}"]
  assume_role {
    role_arn = "arn:aws:iam::${local.logging_account}:role/cds-siem"
  }
}
EOF
}

generate "common_variables" {
  path      = "common_variables.tf"
  if_exists = "overwrite"
  contents  = <<EOF
variable "account_id" {
  description = "(Required) The account ID to perform actions on."
  type        = string
}

variable "caller_arn" {
  description = "(Required) The caller's ARN."
  type        = string
}

variable "env" {
  description = "The current running environment"
  type        = string
}

variable "product_name" {
  description = "(Required) The name of the product you are deploying."
  type        = string
}

variable "region" {
  description = "The current AWS region"
  type        = string
}
EOF
}

remote_state {
  backend = "s3"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    encrypt             = true
    bucket              = "${local.product_name}-${local.env}-${get_aws_account_id()}-tf"
    dynamodb_table      = "terraform-state-lock-dynamo"
    region              = "ca-central-1"
    key                 = "${path_relative_to_include()}/terraform.tfstate"
    s3_bucket_tags      = { CostCenter : "${local.product_name}-${local.env}" }
    dynamodb_table_tags = { CostCenter : "${local.product_name}-${local.env}" }
  }
}
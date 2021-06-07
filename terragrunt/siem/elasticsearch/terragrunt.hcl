terraform {
  source = "../../../aws/siem//elasticsearch"
}

include {
  path = find_in_parent_folders()
}

inputs = {
  account_id = get_aws_account_id()
}
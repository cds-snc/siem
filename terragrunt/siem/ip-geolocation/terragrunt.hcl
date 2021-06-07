terraform {
  source = "../../../aws/siem//ip-geolocation"
}

include {
  path = find_in_parent_folders()
}

inputs = {
  account_id = get_aws_account_id()
}
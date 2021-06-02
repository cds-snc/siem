terraform {
  source = "../../../aws//ip-geolocation"
}

include {
  path = find_in_parent_folders()
}


inputs = {
  account_id = 370045664819
}
resource "elasticsearch_opendistro_roles_mapping" "map_all_access_role" {
  role_name   = "all_access"
  description = "Mapping AWS IAM roles to ES all_access role"
  backend_roles = [
    var.cds_siem_admin_role_arn,
    "arn:aws:iam::370045664819:role/aws-reserved/sso.amazonaws.com/ca-central-1/AWSReservedSSO_AdministratorAccess_158d226c84e5830a"
  ]
}

resource "elasticsearch_opendistro_roles_mapping" "map_security_manager_role" {
  role_name   = "security_manager"
  description = "Mapping AWS IAM roles to ES security_manager role"
  backend_roles = [
    var.cds_siem_admin_role_arn,
    "arn:aws:iam::370045664819:role/aws-reserved/sso.amazonaws.com/ca-central-1/AWSReservedSSO_AdministratorAccess_158d226c84e5830a"
  ]
}

resource "elasticsearch_opendistro_role" "cds_siem_loader" {
  role_name   = "cds_siem_loader"
  description = "Loads logs"

  cluster_permissions = ["cluster_monitor",
    "cluster_composite_ops",
    "indices:admin/template/get",
    "indices:admin/template/put",
    "cluster:admin/ingest/pipeline/put",
    "cluster:admin/ingest/pipeline/get"
  ]

  index_permissions {
    index_patterns  = ["log-*"]
    allowed_actions = ["crud", "create_index"]
  }
}
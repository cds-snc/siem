resource "elasticsearch_opendistro_roles_mapping" "map_all_access_role" {
  role_name   = "all_access"
  description = "Mapping AWS IAM roles to ES all_access role"
  backend_roles = [
    var.cds_siem_admin_role_arn,
    var.kibana_admin_role
  ]
  users = [
    var.kibana_admin_role
  ]
}

resource "elasticsearch_opendistro_roles_mapping" "map_security_manager_role" {
  role_name   = "security_manager"
  description = "Mapping AWS IAM roles to ES security_manager role"
  backend_roles = [
    var.cds_siem_admin_role_arn,
    var.kibana_admin_role
  ]
  users = [
    var.kibana_admin_role
  ]
}

resource "elasticsearch_opendistro_roles_mapping" "map_manage_snapshots_role" {
  role_name   = "manage_snapshots"
  description = "Mapping AWS IAM roles to ES manage_snapshots role"
  backend_roles = [
    aws_iam_role.cds_siem_snapshot_role.arn
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

resource "elasticsearch_opendistro_roles_mapping" "map_cds_siem_loader_role" {
  role_name   = "cds_siem_loader"
  description = "Mapping AWS IAM roles to ES cds_siem_loader role"
  backend_roles = [
    aws_iam_role.cds_siem_loader_role.arn,
  ]
}
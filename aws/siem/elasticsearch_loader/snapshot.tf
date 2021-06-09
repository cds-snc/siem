resource "elasticsearch_snapshot_repository" "cds_siem" {
  name = "cds-siem"
  type = "s3"
  settings = {
    base_path = "manual"
    bucket    = aws_s3_bucket.cds_siem_snapshots.bucket
    region    = var.region
    role_arn  = aws_iam_role.cds_siem_snapshot_role.arn
  }
  depends_on = [
    aws_s3_bucket.cds_siem_snapshots,
    aws_iam_role.cds_siem_snapshot_role,
    elasticsearch_opendistro_roles_mapping.map_manage_snapshots_role
  ]
}

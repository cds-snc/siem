output "es_endpoint" {
  value = aws_elasticsearch_domain.cds_siem.endpoint
}

output "cds_siem_admin_role_arn" {
  value = aws_iam_role.cds_siem_admin_role.arn
}
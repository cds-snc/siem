resource "aws_ecr_repository" "ip_geolocation" {
  # checkov:skip=CKV_AWS_51:The :latest tag is used in Staging

  name                 = "siem/ip-geolocation"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
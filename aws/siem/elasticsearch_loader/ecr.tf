resource "aws_ecr_repository" "loader" {
  # checkov:skip=CKV_AWS_51:The :latest tag is used in Staging

  name                 = "siem/loader"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
variable "logs_destination_bucket_arn" {
  type        = string
  description = "CDS SIEM destination bucket ARN"
}

variable "logs_destination_bucket_id" {
  type        = string
  description = "CDS SIEM destination bucket ID"
}

variable "cloud_trail_replication_role" {
  type        = string
  description = "IAM Role for CloudTrail replication"
}

variable "security_hub_replication_role" {
  type        = string
  description = "IAM Role for SecurityHub replication"
}
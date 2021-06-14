variable "guard_duty_replication_role" {
  type        = string
  description = "IAM Role for GuardDuty replication"
}

variable "logs_destination_bucket_arn" {
  type        = string
  description = "CDS SIEM destination bucket ARN"
}

variable "logs_destination_bucket_id" {
  type        = string
  description = "CDS SIEM destination bucket ID"
}

variable "security_hub_replication_role" {
  type        = string
  description = "IAM Role for SecurityHub replication"
}
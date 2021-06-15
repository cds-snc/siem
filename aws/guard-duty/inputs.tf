variable "loader_function_arn" {
  type        = string
  description = "CDS SIEM loader function ARN"
}

variable "loader_function_name" {
  type        = string
  description = "CDS SIEM loader function name"
}

variable "loader_function_role" {
  type        = string
  description = "CDS SIEM loader function role"
}

variable "logs_destination_bucket_arn" {
  type        = string
  description = "CDS SIEM destination bucket ARN"
}

variable "logs_destination_bucket_id" {
  type        = string
  description = "CDS SIEM destination bucket ID"
}
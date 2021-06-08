###
# ElasticSearch Configuration
### 

variable "cds_siem_admin_role_arn" {
  type        = string
  description = "CDS SIEM Admin role ARN"
}

variable "es_endpoint" {
  type        = string
  description = "ElasticSeach endpoint"
}

variable "ip_geolocation_bucket_arn" {
  type        = string
  description = "IP Geolocation ARN"
}

variable "ip_geolocation_bucket" {
  type        = string
  description = "IP Geolocation name"
}

variable "rollover_indexes" {
  type        = list(string)
  description = "List of indexes that should be rolled over at 100 GB"
  default = [
    "log-aws-cloudtrail",
    "log-aws-cloudfront",
    "log-aws-guardduty",
    "log-aws-elb",
    "log-aws-r53resolver",
    "log-aws-s3accesslog",
    "log-aws-securityhub",
    "log-aws-vpcflowlogs",
    "log-aws-waf",
    "log-aws-msk",
    "log-linux-secure",
    "log-linux-os",
  ]
}
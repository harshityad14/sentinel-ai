variable "project_name" {
  type        = string
  description = "Project name"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs for ALB placement"
}

variable "security_group_id" {
  type        = string
  description = "Security group ID for the ALB"
}

variable "ssl_certificate_arn" {
  type        = string
  description = "ACM SSL Certificate ARN (optional)"
  default     = ""
}

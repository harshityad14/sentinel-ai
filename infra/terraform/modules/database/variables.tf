variable "project_name" {
  type        = string
  description = "Project name"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for database placement"
}

variable "security_group_id" {
  type        = string
  description = "Security group ID for PostgreSQL"
}

variable "instance_class" {
  type        = string
  description = "RDS instance class"
  default     = "db.t4g.medium"
}

variable "allocated_storage" {
  type        = number
  description = "Allocated storage in GB"
  default     = 50
}

variable "db_name" {
  type        = string
  description = "Database name"
  default     = "sentinel_db"
}

variable "db_username" {
  type        = string
  description = "Master database username"
  default     = "sentinel_admin"
}

variable "secrets_manager_db_secret_arn" {
  type        = string
  description = "ARN of Secrets Manager secret containing database master password"
}

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
  description = "Private subnets for ECS tasks"
}

variable "security_group_id" {
  type        = string
  description = "Security group ID for ECS tasks"
}

variable "api_target_group_arn" {
  type        = string
  description = "ALB target group ARN for the API"
}

variable "api_image" {
  type        = string
  description = "Container image for API"
}

variable "worker_image" {
  type        = string
  description = "Container image for Streaming Worker"
}

variable "api_cpu" {
  type        = number
  description = "CPU units for API task"
  default     = 512
}

variable "api_memory" {
  type        = number
  description = "Memory for API task in MB"
  default     = 1024
}

variable "worker_cpu" {
  type        = number
  description = "CPU units for Worker task"
  default     = 512
}

variable "worker_memory" {
  type        = number
  description = "Memory for Worker task in MB"
  default     = 1024
}

variable "api_desired_count" {
  type        = number
  description = "Desired number of API task replicas"
  default     = 2
}

variable "worker_desired_count" {
  type        = number
  description = "Desired number of Worker task replicas"
  default     = 2
}

variable "db_secret_arn" {
  type        = string
  description = "Secrets Manager ARN for database credentials"
}

variable "ai_secret_arn" {
  type        = string
  description = "Secrets Manager ARN for AI Provider credentials (optional)"
  default     = ""
}

variable "kafka_bootstrap_servers" {
  type        = string
  description = "Kafka cluster bootstrap servers"
  default     = "kafka:9092"
}

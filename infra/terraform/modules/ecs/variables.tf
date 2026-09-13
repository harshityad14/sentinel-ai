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

variable "vpc_id" {
  type        = string
  description = "VPC ID for Cloud Map service discovery"
}

variable "kafka_security_group_id" {
  type        = string
  description = "Security group ID for internal Kafka broker"
}

variable "kafka_image" {
  type        = string
  description = "Container image for internal Apache Kafka KRaft broker"
  default     = "apache/kafka:3.7.0"
}

variable "kafka_bootstrap_servers" {
  type        = string
  description = "External Kafka bootstrap servers (optional; if empty, uses internal ECS Kafka service discovery)"
  default     = ""
}

variable "web_image" {
  type        = string
  description = "Container image for Web frontend"
}

variable "web_target_group_arn" {
  type        = string
  description = "ALB target group ARN for Web frontend"
}

variable "web_cpu" {
  type        = number
  description = "CPU units for Web task"
  default     = 256
}

variable "web_memory" {
  type        = number
  description = "Memory for Web task in MB"
  default     = 512
}

variable "web_desired_count" {
  type        = number
  description = "Desired number of Web task replicas"
  default     = 2
}

variable "trusted_hosts" {
  type        = list(string)
  description = "Explicit trusted host headers for API"
  default     = ["localhost", "127.0.0.1", "web", "api"]
}

variable "cors_origins" {
  type        = list(string)
  description = "Explicit CORS allowed origins for API"
  default     = ["http://localhost:8080"]
}

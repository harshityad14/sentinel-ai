variable "aws_region" {
  description = "Target AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project identifier for resource naming and tagging"
  type        = string
  default     = "sentinel-ai"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "api_cpu" {
  description = "CPU units for API Fargate task (256, 512, 1024, etc.)"
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memory (MB) for API Fargate task (512, 1024, 2048, etc.)"
  type        = number
  default     = 1024
}

variable "worker_cpu" {
  description = "CPU units for Worker Fargate task"
  type        = number
  default     = 512
}

variable "worker_memory" {
  description = "Memory (MB) for Worker Fargate task"
  type        = number
  default     = 1024
}

variable "api_desired_count" {
  description = "Number of API task replicas"
  type        = number
  default     = 2
}

variable "worker_desired_count" {
  description = "Number of Streaming Worker task replicas"
  type        = number
  default     = 2
}

variable "db_instance_class" {
  description = "RDS instance type"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Initial allocated storage in GB for RDS"
  type        = number
  default     = 50
}

variable "api_image" {
  description = "ECR Image URI for the API container"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sentinel-api:v0.5.0"
}

variable "web_image" {
  description = "ECR Image URI for the Web frontend container"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sentinel-web:v0.5.0"
}

variable "worker_image" {
  description = "ECR Image URI for the Streaming Worker container"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sentinel-worker:v0.5.0"
}

variable "secrets_manager_db_secret_arn" {
  description = "ARN of AWS Secrets Manager secret storing PostgreSQL credentials"
  type        = string
  default     = "arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/production/db-credentials-aBcDeF"
}

variable "secrets_manager_ai_secret_arn" {
  description = "ARN of AWS Secrets Manager secret storing GenAI API key (optional)"
  type        = string
  default     = ""
}

variable "ssl_certificate_arn" {
  description = "ACM SSL Certificate ARN for ALB HTTPS listener (optional)"
  type        = string
  default     = ""
}

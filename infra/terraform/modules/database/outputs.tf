output "db_endpoint" {
  description = "PostgreSQL endpoint address"
  value       = aws_db_instance.main.endpoint
}

output "db_address" {
  description = "PostgreSQL hostname"
  value       = aws_db_instance.main.address
}

output "db_port" {
  description = "PostgreSQL port"
  value       = aws_db_instance.main.port
}

output "db_secret_arn" {
  description = "Secrets Manager secret ARN containing generated credentials"
  value       = try(aws_db_instance.main.master_user_secret[0].secret_arn, var.secrets_manager_db_secret_arn)
}

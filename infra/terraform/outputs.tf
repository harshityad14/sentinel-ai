output "alb_dns_name" {
  description = "Public entrypoint URL for SentinelAI platform"
  value       = module.alb.alb_dns_name
}

output "ecs_cluster_name" {
  description = "ECS Cluster Name"
  value       = module.ecs.cluster_name
}

output "api_service_name" {
  description = "ECS API Service Name"
  value       = module.ecs.api_service_name
}

output "worker_service_name" {
  description = "ECS Worker Service Name"
  value       = module.ecs.worker_service_name
}

output "migration_task_definition" {
  description = "Migration task definition ARN for pre-deployment invocation"
  value       = module.ecs.migration_task_definition_arn
}

output "database_endpoint" {
  description = "PostgreSQL connection endpoint (internal private subnet only)"
  value       = module.database.db_endpoint
}

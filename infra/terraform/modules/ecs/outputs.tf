output "cluster_id" {
  description = "ID of ECS cluster"
  value       = aws_ecs_cluster.main.id
}

output "cluster_name" {
  description = "Name of ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "api_service_name" {
  description = "Name of API ECS service"
  value       = aws_ecs_service.api.name
}

output "worker_service_name" {
  description = "Name of Streaming Worker ECS service"
  value       = aws_ecs_service.worker.name
}

output "migration_task_definition_arn" {
  description = "ARN of Migration one-off task definition"
  value       = aws_ecs_task_definition.migration.arn
}

output "web_service_name" {
  description = "Name of Web frontend ECS service"
  value       = aws_ecs_service.web.name
}

output "kafka_service_name" {
  description = "Name of Kafka ECS service"
  value       = aws_ecs_service.kafka.name
}

output "kafka_endpoint" {
  description = "Bootstrap endpoint for Kafka streaming bus"
  value       = local.kafka_endpoint
}

output "alb_security_group_id" {
  description = "ID of ALB security group"
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "ID of ECS tasks security group"
  value       = aws_security_group.ecs.id
}

output "rds_security_group_id" {
  description = "ID of RDS security group"
  value       = aws_security_group.rds.id
}

output "msk_security_group_id" {
  description = "ID of MSK / Kafka security group"
  value       = aws_security_group.msk.id
}

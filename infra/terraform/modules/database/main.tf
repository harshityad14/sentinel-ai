resource "aws_kms_key" "rds" {
  description             = "KMS key for SentinelAI PostgreSQL RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-rds-kms"
    Environment = var.environment
  }
}

resource "aws_db_subnet_group" "main" {
  name        = "${var.project_name}-${var.environment}-db-subnet-group"
  subnet_ids  = var.private_subnet_ids
  description = "Subnet group for SentinelAI PostgreSQL database"

  tags = {
    Name        = "${var.project_name}-${var.environment}-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project_name}-${var.environment}-postgres"
  engine         = "postgres"
  engine_version = "16.2"
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = 200
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_name  = var.db_name
  username = var.db_username

  # Secrets Manager integration: Master password managed securely by AWS Secrets Manager
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds.arn

  multi_az               = true
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [var.security_group_id]

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Sun:04:30-Sun:05:30"
  auto_minor_version_upgrade = true
  skip_final_snapshot     = true
  deletion_protection     = false

  tags = {
    Name        = "${var.project_name}-${var.environment}-postgres"
    Environment = var.environment
  }
}

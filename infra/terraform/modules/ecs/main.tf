resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-cluster"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = 30

  tags = {
    Name        = "${var.project_name}-${var.environment}-ecs-logs"
    Environment = var.environment
  }
}

# IAM Role: ECS Task Execution Role (Pulls images from ECR, fetches secrets from Secrets Manager)
resource "aws_iam_role" "execution" {
  name = "${var.project_name}-${var.environment}-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "execution_standard" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Least-privilege Secrets Manager access policy for Task Execution Role
resource "aws_iam_policy" "secrets_access" {
  name        = "${var.project_name}-${var.environment}-secrets-access-policy"
  description = "Allows ECS agent to resolve specific SentinelAI secret ARNs at container boot"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = compact([
          var.db_secret_arn,
          var.ai_secret_arn != "" ? var.ai_secret_arn : null
        ])
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "execution_secrets" {
  role       = aws_iam_role.execution.name
  policy_arn = aws_iam_policy.secrets_access.policy_arn
}

# IAM Role: ECS Task Role (Runtime permissions for the running application - strictly passive)
resource "aws_iam_role" "task" {
  name = "${var.project_name}-${var.environment}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })
}

# ==============================================================================
# One-off Schema Migration Task Definition (Executed once prior to rolling update)
# ==============================================================================
resource "aws_ecs_task_definition" "migration" {
  family                   = "${var.project_name}-${var.environment}-migration"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "migration"
      image     = var.api_image
      essential = true
      user      = "10001"
      command   = ["alembic", "upgrade", "head"]
      environment = [
        { name = "SENTINEL_ENV", value = var.environment }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = "${var.db_secret_arn}:connection_url::" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "migration"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}-migration-task"
    Environment = var.environment
  }
}

# ==============================================================================
# API Task Definition & Long-Running Service
# ==============================================================================
resource "aws_ecs_task_definition" "api" {
  family                   = "${var.project_name}-${var.environment}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.api_cpu)
  memory                   = tostring(var.api_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.api_image
      essential = true
      user      = "10001"
      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "SENTINEL_ENV", value = var.environment },
        { name = "API_HOST", value = "0.0.0.0" },
        { name = "API_PORT", value = "8000" },
        { name = "LOG_LEVEL", value = "INFO" },
        { name = "KAFKA_BOOTSTRAP_SERVERS", value = var.kafka_bootstrap_servers }
      ]
      secrets = compact([
        { name = "DATABASE_URL", valueFrom = "${var.db_secret_arn}:connection_url::" },
        { name = "POSTGRES_PASSWORD", valueFrom = "${var.db_secret_arn}:password::" },
        var.ai_secret_arn != "" ? { name = "SENTINEL_AI_API_KEY", valueFrom = var.ai_secret_arn } : null
      ])
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "api"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}-api-task"
    Environment = var.environment
  }
}

resource "aws_ecs_service" "api" {
  name            = "${var.project_name}-${var.environment}-api-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.api_target_group_arn
    container_name   = "api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-api-service"
    Environment = var.environment
  }
}

# ==============================================================================
# Streaming Worker Task Definition & Long-Running Service
# ==============================================================================
resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.project_name}-${var.environment}-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.worker_cpu)
  memory                   = tostring(var.worker_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = var.worker_image
      essential = true
      user      = "10002"
      command   = ["python", "-m", "sentinel_streaming.runner"]
      environment = [
        { name = "SENTINEL_ENV", value = var.environment },
        { name = "LOG_LEVEL", value = "INFO" },
        { name = "KAFKA_BOOTSTRAP_SERVERS", value = var.kafka_bootstrap_servers }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = "${var.db_secret_arn}:connection_url::" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}-worker-task"
    Environment = var.environment
  }
}

resource "aws_ecs_service" "worker" {
  name            = "${var.project_name}-${var.environment}-worker-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-worker-service"
    Environment = var.environment
  }
}

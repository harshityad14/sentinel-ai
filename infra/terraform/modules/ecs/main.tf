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

locals {
  kafka_endpoint = var.kafka_bootstrap_servers != "" ? var.kafka_bootstrap_servers : "kafka.${var.project_name}-${var.environment}.local:9092"
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
  policy_arn = aws_iam_policy.secrets_access.arn
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
# Internal Service Discovery (Cloud Map Private DNS)
# ==============================================================================
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "${var.project_name}-${var.environment}.local"
  description = "Private DNS namespace for SentinelAI internal services"
  vpc         = var.vpc_id

  tags = {
    Name        = "${var.project_name}-${var.environment}-private-dns"
    Environment = var.environment
  }
}

resource "aws_service_discovery_service" "kafka" {
  name = "kafka"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-kafka-discovery"
    Environment = var.environment
  }
}

# ==============================================================================
# Apache Kafka (KRaft) Task Definition & Long-Running Service
# ==============================================================================
resource "aws_ecs_task_definition" "kafka" {
  family                   = "${var.project_name}-${var.environment}-kafka"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "kafka"
      image     = var.kafka_image
      essential = true
      portMappings = [
        {
          containerPort = 9092
          hostPort      = 9092
          protocol      = "tcp"
        },
        {
          containerPort = 9093
          hostPort      = 9093
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "KAFKA_NODE_ID", value = "1" },
        { name = "KAFKA_PROCESS_ROLES", value = "broker,controller" },
        { name = "KAFKA_LISTENERS", value = "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093" },
        { name = "KAFKA_ADVERTISED_LISTENERS", value = "PLAINTEXT://kafka.${var.project_name}-${var.environment}.local:9092" },
        { name = "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", value = "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT" },
        { name = "KAFKA_CONTROLLER_LISTENER_NAMES", value = "CONTROLLER" },
        { name = "KAFKA_INTER_BROKER_LISTENER_NAME", value = "PLAINTEXT" },
        { name = "KAFKA_CONTROLLER_QUORUM_VOTERS", value = "1@127.0.0.1:9093" },
        { name = "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", value = "1" },
        { name = "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", value = "1" },
        { name = "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", value = "1" },
        { name = "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS", value = "0" },
        { name = "KAFKA_NUM_PARTITIONS", value = "6" },
        { name = "KAFKA_AUTO_CREATE_TOPICS_ENABLE", value = "true" }
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 20
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "kafka"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}-kafka-task"
    Environment = var.environment
  }
}

resource "aws_ecs_service" "kafka" {
  name            = "${var.project_name}-${var.environment}-kafka-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.kafka.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.kafka_security_group_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.kafka.arn
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-kafka-service"
    Environment = var.environment
  }
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
        { name = "POSTGRES_USER", valueFrom = "${var.db_secret_arn}:username::" },
        { name = "POSTGRES_PASSWORD", valueFrom = "${var.db_secret_arn}:password::" },
        { name = "POSTGRES_HOST", valueFrom = "${var.db_secret_arn}:host::" },
        { name = "POSTGRES_PORT", valueFrom = "${var.db_secret_arn}:port::" },
        { name = "POSTGRES_DB", valueFrom = "${var.db_secret_arn}:dbname::" }
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
        { name = "KAFKA_BOOTSTRAP_SERVERS", value = local.kafka_endpoint },
        { name = "TRUSTED_HOSTS", value = join(",", var.trusted_hosts) },
        { name = "CORS_ORIGINS", value = join(",", var.cors_origins) }
      ]
      secrets = concat(
        [
          { name = "POSTGRES_USER", valueFrom = "${var.db_secret_arn}:username::" },
          { name = "POSTGRES_PASSWORD", valueFrom = "${var.db_secret_arn}:password::" },
          { name = "POSTGRES_HOST", valueFrom = "${var.db_secret_arn}:host::" },
          { name = "POSTGRES_PORT", valueFrom = "${var.db_secret_arn}:port::" },
          { name = "POSTGRES_DB", valueFrom = "${var.db_secret_arn}:dbname::" }
        ],
        var.ai_secret_arn != "" ? [{ name = "SENTINEL_AI_API_KEY", valueFrom = var.ai_secret_arn }] : []
      )
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
# Web Frontend Task Definition & Long-Running Service
# ==============================================================================
resource "aws_ecs_task_definition" "web" {
  family                   = "${var.project_name}-${var.environment}-web"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.web_cpu)
  memory                   = tostring(var.web_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "web"
      image     = var.web_image
      essential = true
      user      = "101"
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "web"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}-web-task"
    Environment = var.environment
  }
}

resource "aws_ecs_service" "web" {
  name            = "${var.project_name}-${var.environment}-web-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.web.arn
  desired_count   = var.web_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.web_target_group_arn
    container_name   = "web"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-web-service"
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
        { name = "KAFKA_BOOTSTRAP_SERVERS", value = local.kafka_endpoint }
      ]
      secrets = [
        { name = "POSTGRES_USER", valueFrom = "${var.db_secret_arn}:username::" },
        { name = "POSTGRES_PASSWORD", valueFrom = "${var.db_secret_arn}:password::" },
        { name = "POSTGRES_HOST", valueFrom = "${var.db_secret_arn}:host::" },
        { name = "POSTGRES_PORT", valueFrom = "${var.db_secret_arn}:port::" },
        { name = "POSTGRES_DB", valueFrom = "${var.db_secret_arn}:dbname::" }
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

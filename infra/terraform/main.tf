terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }

  # Production state backend: S3 + DynamoDB locking
  # backend "s3" {
  #   bucket         = "sentinel-ai-terraform-state"
  #   key            = "production/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "sentinel-ai-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      PassiveMode = "Strict"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# 1. Network Topology (VPC, Subnets, NAT, IGW)
module "vpc" {
  source             = "./modules/vpc"
  project_name       = var.project_name
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
}

# 2. Security Groups (Least-privilege isolation)
module "security" {
  source       = "./modules/security"
  project_name = var.project_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
}

# 3. Application Load Balancer
module "alb" {
  source              = "./modules/alb"
  project_name        = var.project_name
  environment         = var.environment
  vpc_id              = module.vpc.vpc_id
  public_subnet_ids   = module.vpc.public_subnet_ids
  security_group_id   = module.security.alb_security_group_id
  ssl_certificate_arn = var.ssl_certificate_arn
}

# 4. Persistence Layer (Multi-AZ PostgreSQL RDS with KMS encryption)
module "database" {
  source                        = "./modules/database"
  project_name                  = var.project_name
  environment                   = var.environment
  private_subnet_ids            = module.vpc.private_subnet_ids
  security_group_id             = module.security.rds_security_group_id
  instance_class                = var.db_instance_class
  allocated_storage             = var.db_allocated_storage
  secrets_manager_db_secret_arn = var.secrets_manager_db_secret_arn
}

# 5. Compute Orchestration (ECS Fargate, Task Definitions, Roles)
module "ecs" {
  source                  = "./modules/ecs"
  project_name            = var.project_name
  environment             = var.environment
  vpc_id                  = module.vpc.vpc_id
  private_subnet_ids      = module.vpc.private_subnet_ids
  security_group_id       = module.security.ecs_security_group_id
  kafka_security_group_id = module.security.msk_security_group_id
  api_target_group_arn    = module.alb.api_target_group_arn
  web_target_group_arn    = module.alb.web_target_group_arn
  api_image               = var.api_image
  web_image               = var.web_image
  worker_image            = var.worker_image
  kafka_image             = var.kafka_image
  kafka_bootstrap_servers = var.kafka_bootstrap_servers
  api_cpu                 = var.api_cpu
  api_memory              = var.api_memory
  worker_cpu              = var.worker_cpu
  worker_memory           = var.worker_memory
  web_cpu                 = var.web_cpu
  web_memory              = var.web_memory
  api_desired_count       = var.api_desired_count
  worker_desired_count    = var.worker_desired_count
  web_desired_count       = var.web_desired_count
  db_secret_arn           = module.database.db_secret_arn
  ai_secret_arn           = var.secrets_manager_ai_secret_arn

  trusted_hosts = distinct(compact(concat(
    var.trusted_hosts,
    [module.alb.alb_dns_name],
    var.custom_domain != "" ? [var.custom_domain] : []
  )))

  cors_origins = distinct(compact(concat(
    var.cors_origins,
    ["http://${module.alb.alb_dns_name}", "https://${module.alb.alb_dns_name}"],
    var.custom_domain != "" ? ["http://${var.custom_domain}", "https://${var.custom_domain}"] : []
  )))
}

"""Unit tests for Phase 9 DevOps configuration, production fail-fast rules, and IaC/Docker invariants."""

import os
import unittest
import yaml
from pathlib import Path
from pydantic import ValidationError

from app.core.config import Settings


class TestProductionConfigValidation(unittest.TestCase):
    """Test suite validating fail-fast behavior of production settings."""

    def test_development_defaults_allowed_in_dev_mode(self):
        """Verify development defaults are valid when SENTINEL_ENV is development."""
        settings = Settings(
            SENTINEL_ENV="development",
            DATABASE_URL="sqlite:///./sentinel.db",
            POSTGRES_PASSWORD=None,
        )
        self.assertEqual(settings.environment, "development")
        self.assertTrue(settings.database_url.startswith("sqlite"))

    def test_missing_postgres_password_fails_in_production(self):
        """Verify missing POSTGRES_PASSWORD raises ValueError in production."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                TRUSTED_HOSTS=["sentinel.domain.com"],
                CORS_ORIGINS=["https://sentinel.domain.com"],
            )
        self.assertIn("POSTGRES_PASSWORD must be explicitly provided", str(ctx.exception))

    def test_default_dev_password_rejected_in_production(self):
        """Verify sentinel_dev_password is strictly forbidden in production."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="sentinel_dev_password",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                TRUSTED_HOSTS=["sentinel.domain.com"],
                CORS_ORIGINS=["https://sentinel.domain.com"],
            )
        self.assertIn("sentinel_dev_password' is strictly forbidden", str(ctx.exception))

    def test_dev_password_in_database_url_rejected_in_production(self):
        """Verify sentinel_dev_password in DATABASE_URL is strictly forbidden in production."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="strong_random_secret_password_123",
                DATABASE_URL="postgresql://user:sentinel_dev_password@localhost:5432/db",
                TRUSTED_HOSTS=["sentinel.domain.com"],
                CORS_ORIGINS=["https://sentinel.domain.com"],
            )
        self.assertIn("sentinel_dev_password", str(ctx.exception))

    def test_sqlite_rejected_in_production(self):
        """Verify SQLite database URL is forbidden in production mode."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="strong_random_secret_password_123",
                DATABASE_URL="sqlite:///./sentinel.db",
                TRUSTED_HOSTS=["sentinel.domain.com"],
                CORS_ORIGINS=["https://sentinel.domain.com"],
            )
        self.assertIn("SQLite database is not permitted in production", str(ctx.exception))

    def test_wildcard_trusted_hosts_rejected_in_production(self):
        """Verify wildcard trusted_hosts is forbidden in production."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="strong_random_secret_password_123",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                TRUSTED_HOSTS=["*"],
                CORS_ORIGINS=["https://sentinel.domain.com"],
            )
        self.assertIn("trusted_hosts must be explicitly configured and cannot contain '*'", str(ctx.exception))

    def test_wildcard_cors_rejected_in_production(self):
        """Verify wildcard cors_origins is forbidden in production."""
        with self.assertRaises(ValidationError) as ctx:
            Settings(
                SENTINEL_ENV="production",
                POSTGRES_PASSWORD="strong_random_secret_password_123",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                TRUSTED_HOSTS=["sentinel.domain.com"],
                CORS_ORIGINS=["*"],
            )
        self.assertIn("cors_origins must be explicitly configured and cannot contain '*'", str(ctx.exception))

    def test_valid_production_settings_pass(self):
        """Verify compliant production configuration validates cleanly."""
        settings = Settings(
            SENTINEL_ENV="production",
            POSTGRES_PASSWORD="strong_random_secret_password_123",
            DATABASE_URL="postgresql://admin:strong_random_secret_password_123@postgres:5432/sentinel_db",
            TRUSTED_HOSTS=["sentinel.domain.com", "api.internal"],
            CORS_ORIGINS=["https://sentinel.domain.com"],
            SENTINEL_AI_PROVIDER="mock",
        )
        self.assertEqual(settings.environment, "production")
        self.assertEqual(settings.postgres_password, "strong_random_secret_password_123")


class TestDockerAndComposeInvariants(unittest.TestCase):
    """Test suite validating Dockerfile and Compose security invariants."""

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent.parent

    def test_dockerfile_api_invariants(self):
        """Audit apps/api/Dockerfile for non-root, multi-stage, and migration omission."""
        api_dockerfile = self.repo_root / "apps" / "api" / "Dockerfile"
        self.assertTrue(api_dockerfile.exists(), "apps/api/Dockerfile must exist")
        content = api_dockerfile.read_text(encoding="utf-8")

        # Multi-stage check
        self.assertIn("AS builder", content)
        self.assertIn("AS runner", content)

        # Non-root user check (numeric UID 10001)
        self.assertTrue("USER 10001" in content or "USER appuser" in content)
        self.assertIn("10001", content)

        # Healthcheck check
        self.assertIn("HEALTHCHECK", content)

        # Migration MUST NOT run automatically in CMD/ENTRYPOINT
        self.assertNotIn("alembic upgrade head", content)

    def test_dockerfile_web_invariants(self):
        """Audit apps/web/Dockerfile for unprivileged nginx and multi-stage build."""
        web_dockerfile = self.repo_root / "apps" / "web" / "Dockerfile"
        self.assertTrue(web_dockerfile.exists(), "apps/web/Dockerfile must exist")
        content = web_dockerfile.read_text(encoding="utf-8")

        self.assertIn("AS builder", content)
        self.assertIn("nginxinc/nginx-unprivileged", content)
        self.assertIn("EXPOSE 8080", content)

    def test_dockerfile_worker_invariants(self):
        """Audit Dockerfile.worker for multi-stage and non-root user."""
        worker_dockerfile = self.repo_root / "Dockerfile.worker"
        self.assertTrue(worker_dockerfile.exists(), "Dockerfile.worker must exist")
        content = worker_dockerfile.read_text(encoding="utf-8")

        self.assertIn("AS builder", content)
        self.assertIn("AS runner", content)
        self.assertTrue("USER 10002" in content or "USER workeruser" in content)
        self.assertIn("10002", content)

    def test_docker_compose_structure(self):
        """Validate docker-compose.yml structure, 6 services, and network isolation."""
        compose_file = self.repo_root / "docker-compose.yml"
        self.assertTrue(compose_file.exists(), "docker-compose.yml must exist")
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8"))

        services = data.get("services", {})
        # Must contain 6 services
        expected_services = {"postgres", "kafka", "migration", "api", "web", "worker"}
        self.assertEqual(set(services.keys()), expected_services)

        # Migration service must be one-off
        migration = services["migration"]
        self.assertEqual(str(migration.get("restart")), "no")
        self.assertIn("alembic upgrade head", " ".join(migration.get("command", [])))

        # API must depend on migration completed successfully
        api = services["api"]
        api_deps = api.get("depends_on", {})
        self.assertIn("migration", api_deps)
        self.assertEqual(api_deps["migration"].get("condition"), "service_completed_successfully")

        # Worker must depend on migration completed successfully
        worker = services["worker"]
        worker_deps = worker.get("depends_on", {})
        self.assertIn("migration", worker_deps)
        self.assertEqual(worker_deps["migration"].get("condition"), "service_completed_successfully")

        # Network exposure audit: Only 'web' may expose host ports
        for s_name, s_conf in services.items():
            if s_name == "web":
                ports = s_conf.get("ports", [])
                self.assertTrue(any("8080" in str(p) for p in ports))
            else:
                self.assertNotIn(
                    "ports",
                    s_conf,
                    f"Service '{s_name}' must NOT expose host ports. Must remain internal to sentinel-net.",
                )


class TestTerraformInvariants(unittest.TestCase):
    """Test suite validating Terraform reference architecture invariants."""

    def setUp(self):
        self.tf_dir = Path(__file__).resolve().parent.parent.parent / "infra" / "terraform"

    def test_terraform_files_exist(self):
        """Confirm all Terraform modules and root manifests exist."""
        required_files = [
            self.tf_dir / "main.tf",
            self.tf_dir / "variables.tf",
            self.tf_dir / "outputs.tf",
            self.tf_dir / "terraform.tfvars.example",
            self.tf_dir / "modules" / "vpc" / "main.tf",
            self.tf_dir / "modules" / "security" / "main.tf",
            self.tf_dir / "modules" / "alb" / "main.tf",
            self.tf_dir / "modules" / "database" / "main.tf",
            self.tf_dir / "modules" / "ecs" / "main.tf",
        ]
        for f in required_files:
            self.assertTrue(f.exists(), f"Terraform manifest missing: {f}")

    def test_terraform_no_plaintext_secrets_or_public_rds(self):
        """Assert zero plaintext passwords and zero public database exposure in Terraform files."""
        for tf_file in self.tf_dir.rglob("*.tf"):
            content = tf_file.read_text(encoding="utf-8")
            self.assertNotIn("sentinel_dev_password", content, f"Hardcoded password in {tf_file}")
            if 'resource "aws_db_instance"' in content:
                self.assertIn("publicly_accessible    = false", content)
                self.assertIn("storage_encrypted     = true", content)

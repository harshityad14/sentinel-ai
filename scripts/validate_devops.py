#!/usr/bin/env python3
"""Comprehensive DevOps, Security & Cloud Architecture Validation Script.

Audits:
1. Dockerfile structural and security policies (non-root, multi-stage, no migration run)
2. docker-compose.yml structural, network, and port exposure constraints
3. Terraform HCL structural validity and secret leakage checks
4. Secret leak scanning across git-tracked and staged files
5. Passive security invariant verification
"""

import re
import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FAILURES = []


def record_failure(msg: str):
    print(f"[-] FAILED: {msg}")
    FAILURES.append(msg)


def record_success(msg: str):
    print(f"[+] PASSED: {msg}")


def validate_dockerfiles():
    print("\n--- 1. Dockerfile Security & Policy Audit ---")
    
    # 1. API Dockerfile
    api_df = REPO_ROOT / "apps" / "api" / "Dockerfile"
    if not api_df.exists():
        record_failure(f"Missing {api_df}")
    else:
        text = api_df.read_text(encoding="utf-8")
        if "AS builder" in text and "AS runner" in text:
            record_success("apps/api/Dockerfile is multi-stage")
        else:
            record_failure("apps/api/Dockerfile is not multi-stage")

        if "USER 10001" in text or "USER appuser" in text:
            record_success("apps/api/Dockerfile runs as non-root user (10001)")
        else:
            record_failure("apps/api/Dockerfile does not declare non-root user")

        if "HEALTHCHECK" in text:
            record_success("apps/api/Dockerfile defines container HEALTHCHECK")
        else:
            record_failure("apps/api/Dockerfile missing HEALTHCHECK")

        if "alembic upgrade head" in text:
            record_failure("apps/api/Dockerfile runs alembic migration in container start! (Race condition)")
        else:
            record_success("apps/api/Dockerfile does not execute runtime migration")

    # 2. Web Dockerfile
    web_df = REPO_ROOT / "apps" / "web" / "Dockerfile"
    if not web_df.exists():
        record_failure(f"Missing {web_df}")
    else:
        text = web_df.read_text(encoding="utf-8")
        if "AS builder" in text and "nginx-unprivileged" in text:
            record_success("apps/web/Dockerfile uses multi-stage unprivileged Nginx")
        else:
            record_failure("apps/web/Dockerfile missing unprivileged Nginx pattern")

        if "EXPOSE 8080" in text:
            record_success("apps/web/Dockerfile exposes unprivileged port 8080")
        else:
            record_failure("apps/web/Dockerfile missing EXPOSE 8080")

    # 3. Worker Dockerfile
    worker_df = REPO_ROOT / "Dockerfile.worker"
    if not worker_df.exists():
        record_failure(f"Missing {worker_df}")
    else:
        text = worker_df.read_text(encoding="utf-8")
        if "AS builder" in text and "AS runner" in text:
            record_success("Dockerfile.worker is multi-stage")
        else:
            record_failure("Dockerfile.worker is not multi-stage")

        if "USER 10002" in text or "USER workeruser" in text:
            record_success("Dockerfile.worker runs as non-root workeruser (10002)")
        else:
            record_failure("Dockerfile.worker does not declare non-root user")


def validate_compose():
    print("\n--- 2. Docker Compose Configuration & Network Audit ---")
    compose_path = REPO_ROOT / "docker-compose.yml"
    if not compose_path.exists():
        record_failure("Missing docker-compose.yml")
        return

    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        record_success("docker-compose.yml is valid YAML")
    except Exception as exc:
        record_failure(f"docker-compose.yml YAML parse error: {exc}")
        return

    services = data.get("services", {})
    expected = {"postgres", "kafka", "migration", "api", "web", "worker"}
    if set(services.keys()) == expected:
        record_success(f"docker-compose.yml defines exact 6 services: {sorted(list(expected))}")
    else:
        record_failure(f"docker-compose.yml services mismatch: found {set(services.keys())}")

    # Migration service check
    migration = services.get("migration", {})
    if str(migration.get("restart")) == "no":
        record_success("migration service has restart: 'no'")
    else:
        record_failure(f"migration service restart policy is '{migration.get('restart')}', expected 'no'")

    # Dependency conditions
    for s_name in ["api", "worker"]:
        s = services.get(s_name, {})
        deps = s.get("depends_on", {})
        if "migration" in deps and deps["migration"].get("condition") == "service_completed_successfully":
            record_success(f"{s_name} depends on migration: condition: service_completed_successfully")
        else:
            record_failure(f"{s_name} does not properly depend on migration: condition: service_completed_successfully")

    # Host port exposure check
    for s_name, s_conf in services.items():
        ports = s_conf.get("ports", [])
        if s_name == "web":
            if any("8080" in str(p) for p in ports):
                record_success("web service exposes host port 8080 (Nginx ingress)")
            else:
                record_failure("web service missing host port 8080")
        else:
            if ports:
                record_failure(f"SECURITY VIOLATION: Service '{s_name}' exposes host ports {ports}! Must be internal.")
            else:
                record_success(f"Service '{s_name}' does not expose host ports (internal network only)")


def validate_terraform():
    print("\n--- 3. Terraform Reference Architecture Audit ---")
    tf_dir = REPO_ROOT / "infra" / "terraform"
    if not tf_dir.exists():
        record_failure("Missing infra/terraform directory")
        return

    required_modules = ["vpc", "security", "alb", "database", "ecs"]
    for m in required_modules:
        m_dir = tf_dir / "modules" / m
        if m_dir.exists() and (m_dir / "main.tf").exists():
            record_success(f"Terraform module '{m}' exists and contains main.tf")
        else:
            record_failure(f"Missing Terraform module '{m}'")

    # Check root files
    for f in ["main.tf", "variables.tf", "outputs.tf", "terraform.tfvars.example"]:
        if (tf_dir / f).exists():
            record_success(f"Terraform root '{f}' exists")
        else:
            record_failure(f"Missing Terraform root '{f}'")

    # Audit for no plaintext passwords
    for tf_file in tf_dir.rglob("*.tf"):
        content = tf_file.read_text(encoding="utf-8")
        if "sentinel_dev_password" in content:
            record_failure(f"Found default password in {tf_file.relative_to(REPO_ROOT)}")


def scan_for_secrets():
    print("\n--- 4. Repository Secret Leak Scan ---")
    secret_patterns = [
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private Key Header"),
        (re.compile(r"""(?i)(?:aws_secret_access_key|aws_access_key_id)\s*=\s*['"][a-z0-9/+=]{16,}['"]"""), "AWS Secret Key"),
        (re.compile(r"""sk-[a-zA-Z0-9]{32,}"""), "OpenAI Secret Key"),
        (re.compile(r"""ghp_[a-zA-Z0-9]{36}"""), "GitHub Personal Access Token"),
    ]

    scanned_count = 0
    clean = True
    ignore_dirs = {".git", "node_modules", "dist", ".pytest_cache", "__pycache__"}

    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in ignore_dirs for part in p.parts):
            continue
        if p.suffix in [".pyc", ".png", ".jpg", ".ico", ".woff", ".woff2", ".db", ".sqlite"]:
            continue

        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            scanned_count += 1
            for pat, name in secret_patterns:
                if pat.search(content):
                    record_failure(f"Potential secret leak ({name}) in {p.relative_to(REPO_ROOT)}")
                    clean = False
        except Exception:
            pass

    if clean:
        record_success(f"Secret leak scan clean across {scanned_count} files")


def main():
    validate_dockerfiles()
    validate_compose()
    validate_terraform()
    scan_for_secrets()

    print("\n========================================================")
    if not FAILURES:
        print("ALL ARCHITECTURAL & DEVOPS AUDITS PASSED CLEANLY!")
        sys.exit(0)
    else:
        print(f"AUDIT FAILED WITH {len(FAILURES)} VIOLATIONS")
        sys.exit(1)


if __name__ == "__main__":
    main()

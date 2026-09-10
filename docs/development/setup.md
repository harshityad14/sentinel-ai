# SentinelAI — Developer Environment Setup Guide

This guide describes how to configure your local development environment for **SentinelAI** across Phase 0 and subsequent phases.

---

## 1. Prerequisites

Ensure the following tools are installed on your machine:
- **Python:** 3.11 or higher (`python --version`)
- **Node.js:** 20 LTS or higher (`node --version`)
- **Git:** 2.35 or higher (`git --version`)
- **Docker & Docker Compose:** Optional for Phase 0, recommended for containerized testing (`docker --version`)

---

## 2. Repository Cloning & Python Virtual Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/harshityad14/sentinel-ai.git
   cd sentinel-ai
   ```

2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Upgrade pip and build tools:
   ```bash
   pip install --upgrade pip setuptools wheel
   ```

---

## 3. Package Installation (Editable Mode)

SentinelAI uses a modular package structure. In Phase 0, install the packages in editable mode (`-e`) so that local changes are reflected immediately without re-installing:

```bash
# Core Domain Models
pip install -e packages/models

# Modular System Packages
pip install -e packages/ingestion
pip install -e packages/flow_engine
pip install -e packages/features
pip install -e packages/detection
pip install -e packages/ai_agent
```

---

## 4. Environment Configuration

1. Copy the template configuration:
   ```bash
   cp .env.example .env
   ```

2. Inspect `.env` and configure settings as desired. The defaults are pre-configured for standalone local development.

---

## 5. Verification & Testing

Run the Phase 0 sanity test suite to verify that all packages and models instantiate cleanly:

```bash
python -m unittest discover -s tests/unit
```

Expected output:
```
...
----------------------------------------------------------------------
Ran 2 tests in 0.05s

OK
```

---

## 6. Docker Development (Optional)

In Phase 0, Docker Compose is a lightweight placeholder. No heavy infrastructure (Kafka, PostgreSQL, Redis) is required to run Phase 0.

To inspect the development compose configuration:
```bash
docker compose config
```

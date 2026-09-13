.PHONY: help build up down test test-frontend test-ai audit demo-replay clean tf-validate

PYTHONPATH := packages/models:packages/ingestion:packages/flow_engine:packages/features:packages/detection:packages/correlation:packages/streaming:packages/ai_agent:apps/api

help:
	@echo "SentinelAI Operations Makefile"
	@echo "---------------------------------------------------------"
	@echo "  make build          - Build Docker container images"
	@echo "  make up             - Start production-grade Docker Compose stack"
	@echo "  make down           - Stop Docker Compose stack and clean networks"
	@echo "  make test           - Run backend unit tests"
	@echo "  make test-frontend  - Run frontend test suite"
	@echo "  make test-ai        - Run GenAI evaluation benchmarks"
	@echo "  make audit          - Run SAST, dependency, and passive security audits"
	@echo "  make demo-replay    - Replay synthetic flows into Kafka pipeline"
	@echo "  make tf-validate    - Validate Terraform reference architecture"
	@echo "  make clean          - Remove temporary files and caches"

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down --remove-orphans

test:
	python -m unittest discover -s tests/unit

test-frontend:
	npm --prefix apps/web test -- --run

test-ai:
	python -m unittest tests/benchmarks/test_ai_evaluation.py

audit:
	python -m unittest tests/unit/test_passive_security.py
	bandit -r apps/ packages/ -x tests/ -s B101,B104

demo-replay:
	python scripts/demo_replay.py --count 20

train-ml:
	python scripts/train_model.py

benchmark-ml:
	python tests/benchmarks/benchmark_ml_inference.py --count 200

tf-validate:
	cd infra/terraform && terraform init -backend=false && terraform validate

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf dist build *.egg-info apps/web/dist

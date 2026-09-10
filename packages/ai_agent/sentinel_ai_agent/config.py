"""Configuration settings and parameters for the SentinelAI GenAI Security Analyst."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AIAnalystConfig:
    """Runtime configuration for the GenAI Security Analyst service."""
    provider: str = "mock"  # "mock", "openai", "anthropic", "ollama"
    model_name: str = "mock-analyst-v1"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.0
    qa_temperature: float = 0.2
    max_tokens: int = 1000
    timeout_seconds: float = 15.0
    max_retries: int = 2
    retry_backoff_base: float = 0.5
    cache_ttl_seconds: int = 3600
    cache_max_entries: int = 1000
    rate_limit_rpm: int = 20
    max_context_tokens: int = 2000
    max_question_length: int = 500
    prompt_version: str = "v1.0"

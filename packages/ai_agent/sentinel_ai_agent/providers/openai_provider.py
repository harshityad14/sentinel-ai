"""OpenAI-compatible LLM Provider implementation (supports OpenAI, Azure, vLLM, Ollama)."""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, Type, TypeVar

import httpx

from sentinel_ai_agent.providers.adapter import ProviderNormalizationAdapter
from sentinel_ai_agent.providers.base import BaseLLMProvider

logger = logging.getLogger("sentinel.ai.openai")
T = TypeVar("T")


class OpenAICompatibleProvider(BaseLLMProvider):
    """Provider adapter for OpenAI and compatible endpoints (vLLM, Ollama, LocalAI)."""

    def __init__(
        self,
        model_name: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 2,
        retry_backoff: float = 0.5,
    ):
        self.model_name = model_name
        self.api_key = api_key or ""
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

    async def generate_structured(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Type[T],
        temperature: float = 0.0,
        max_tokens: int = 1000,
        timeout_seconds: float = 15.0,
    ) -> T:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        resp.raise_for_status()

                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return ProviderNormalizationAdapter.parse_and_validate(content, response_schema)
            except Exception as e:
                last_error = e
                logger.warning(
                    "OpenAI provider request attempt %d/%d failed: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (2**attempt))

        raise RuntimeError(f"OpenAICompatibleProvider failed after {self.max_retries + 1} attempts: {last_error}")

    async def check_health(self) -> Dict[str, Any]:
        return {
            "status": "configured" if (self.api_key or "localhost" in self.base_url) else "unconfigured",
            "provider": "openai_compatible",
            "model": self.model_name,
            "base_url": self.base_url,
        }

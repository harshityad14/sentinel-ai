"""Anthropic Claude LLM Provider implementation."""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, Type, TypeVar

import httpx

from sentinel_ai_agent.providers.adapter import ProviderNormalizationAdapter
from sentinel_ai_agent.providers.base import BaseLLMProvider

logger = logging.getLogger("sentinel.ai.anthropic")
T = TypeVar("T")


class AnthropicProvider(BaseLLMProvider):
    """Provider adapter for Anthropic Claude models."""

    def __init__(
        self,
        model_name: str = "claude-3-5-sonnet-20241022",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 2,
        retry_backoff: float = 0.5,
    ):
        self.model_name = model_name
        self.api_key = api_key or ""
        self.base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")
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
        url = f"{self.base_url}/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        tool_def = ProviderNormalizationAdapter.get_anthropic_tool_schema(response_schema)

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "tools": [tool_def],
            "tool_choice": {"type": "tool", "name": tool_def["name"]},
        }

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        resp.raise_for_status()

                    data = resp.json()
                    content_blocks = data.get("content", [])
                    for block in content_blocks:
                        if block.get("type") == "tool_use":
                            input_data = block.get("input", {})
                            return response_schema.model_validate(input_data)

                    # Fallback to text parsing if no tool block
                    text_content = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
                    return ProviderNormalizationAdapter.parse_and_validate(text_content, response_schema)
            except Exception as e:
                last_error = e
                logger.warning(
                    "Anthropic provider request attempt %d/%d failed: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (2**attempt))

        raise RuntimeError(f"AnthropicProvider failed after {self.max_retries + 1} attempts: {last_error}")

    async def check_health(self) -> Dict[str, Any]:
        return {
            "status": "configured" if self.api_key else "unconfigured",
            "provider": "anthropic",
            "model": self.model_name,
            "base_url": self.base_url,
        }

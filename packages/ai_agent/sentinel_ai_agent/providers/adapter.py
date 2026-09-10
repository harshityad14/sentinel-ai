"""Provider structured-output normalization adapters."""

import json
import re
from typing import Any, Dict, Type, TypeVar
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class ProviderNormalizationAdapter:
    """Utilities to normalize structured outputs across disparate LLM provider formats."""

    @staticmethod
    def extract_json_content(raw_text: str) -> Dict[str, Any]:
        """Extract and parse JSON from raw text, code fences, or surrounding text."""
        trimmed = raw_text.strip()
        if trimmed.startswith("{") and trimmed.endswith("}"):
            return json.loads(trimmed)

        # Look for markdown code fence ```json ... ```
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if fence_match:
            return json.loads(fence_match.group(1))

        # Fallback: extract substring between first { and last }
        first_brace = raw_text.find("{")
        last_brace = raw_text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            candidate = raw_text[first_brace : last_brace + 1]
            return json.loads(candidate)

        raise ValueError(f"Could not locate valid JSON in model output: {raw_text[:200]}...")

    @staticmethod
    def parse_and_validate(raw_text: str, schema_cls: Type[T]) -> T:
        """Parse raw model output into a validated Pydantic model instance."""
        json_data = ProviderNormalizationAdapter.extract_json_content(raw_text)
        return schema_cls.model_validate(json_data)

    @staticmethod
    def get_openai_json_schema(schema_cls: Type[T]) -> Dict[str, Any]:
        """Convert a Pydantic schema to OpenAI response_format json_schema."""
        return {
            "type": "json_schema",
            "json_schema": {
                "name": schema_cls.__name__,
                "strict": True,
                "schema": schema_cls.model_json_schema(),
            },
        }

    @staticmethod
    def get_anthropic_tool_schema(schema_cls: Type[T]) -> Dict[str, Any]:
        """Convert a Pydantic schema to an Anthropic tool definition."""
        return {
            "name": f"record_{schema_cls.__name__.lower()}",
            "description": f"Outputs a structured {schema_cls.__name__}",
            "input_schema": schema_cls.model_json_schema(),
        }

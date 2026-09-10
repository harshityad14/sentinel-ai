"""Sanitizer for untrusted network telemetry and analyst inputs."""

import re
from typing import Any, Dict


class TelemetrySanitizer:
    """Sanitizes untrusted telemetry strings and user inputs to prevent prompt injection."""

    # Control characters to strip (ASCII 0-31 except \t, \n, \r)
    CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    # Prompt injection and delimiter breakout patterns to neutralize in telemetry
    INJECTION_PATTERNS = [
        re.compile(r"\[/?(?:INST|SYSTEM|USER|ASSISTANT)\]", re.IGNORECASE),
        re.compile(r"<\/?(?:SYS|telemetry_data|task|system|user|assistant)>", re.IGNORECASE),
        re.compile(r"<\|im_(?:start|end)\|>", re.IGNORECASE),
        re.compile(r"SYSTEM\s+OVERRIDE:?", re.IGNORECASE),
    ]

    @classmethod
    def sanitize_string(cls, val: str, max_length: int = 255) -> str:
        """Strip control characters, neutralize prompt injection markers, and truncate string to max_length."""
        if not isinstance(val, str):
            val = str(val)
        cleaned = cls.CONTROL_CHAR_RE.sub("", val).strip()
        for pattern in cls.INJECTION_PATTERNS:
            cleaned = pattern.sub("", cleaned)
        cleaned = cleaned.strip()
        if len(cleaned) > max_length:
            return cleaned[:max_length] + "..."
        return cleaned

    @classmethod
    def sanitize_analyst_question(cls, question: str, max_length: int = 500) -> str:
        """Sanitize analyst input: length bound, strip control characters, preserve security tokens."""
        if not isinstance(question, str):
            raise ValueError("Analyst question must be a string")
        cleaned = cls.CONTROL_CHAR_RE.sub("", question).strip()
        if len(cleaned) < 3:
            raise ValueError("Analyst question is too short (min 3 characters)")
        if len(cleaned) > max_length:
            raise ValueError(f"Analyst question exceeds maximum length of {max_length} characters")
        return cleaned

    @classmethod
    def sanitize_telemetry_dict(cls, data: Dict[str, Any], max_str_len: int = 255) -> Dict[str, Any]:
        """Recursively sanitize dictionary values for structured JSON telemetry placement."""
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            safe_k = cls.sanitize_string(str(k), max_length=64)
            if isinstance(v, str):
                sanitized[safe_k] = cls.sanitize_string(v, max_length=max_str_len)
            elif isinstance(v, dict):
                sanitized[safe_k] = cls.sanitize_telemetry_dict(v, max_str_len=max_str_len)
            elif isinstance(v, list):
                sanitized[safe_k] = [
                    cls.sanitize_string(item, max_length=max_str_len)
                    if isinstance(item, str)
                    else (
                        cls.sanitize_telemetry_dict(item, max_str_len=max_str_len)
                        if isinstance(item, dict)
                        else item
                    )
                    for item in v
                ]
            else:
                sanitized[safe_k] = v
        return sanitized

"""Observability metrics tracking for the GenAI Security Analyst."""

import time
from typing import Any, Dict, List


class AIMetrics:
    """In-memory operational metrics collector for AI analyst requests."""

    def __init__(self):
        self.requests_total = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.fallbacks_total = 0
        self.grounding_violations_total = 0
        self.tokens_prompt_total = 0
        self.tokens_completion_total = 0
        self._latencies: List[float] = []

    def record_request(self, success: bool = True, is_fallback: bool = False, latency_sec: float = 0.0) -> None:
        self.requests_total += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        if is_fallback:
            self.fallbacks_total += 1
        if latency_sec > 0:
            self._latencies.append(latency_sec)
            if len(self._latencies) > 500:
                self._latencies.pop(0)

    def record_tokens(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.tokens_prompt_total += prompt_tokens
        self.tokens_completion_total += completion_tokens

    def record_grounding_violation(self) -> None:
        self.grounding_violations_total += 1

    def get_summary(self) -> Dict[str, Any]:
        avg_latency = (
            round(sum(self._latencies) / len(self._latencies), 4) if self._latencies else 0.0
        )
        return {
            "requests_total": self.requests_total,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "fallbacks_total": self.fallbacks_total,
            "grounding_violations_total": self.grounding_violations_total,
            "tokens_prompt_total": self.tokens_prompt_total,
            "tokens_completion_total": self.tokens_completion_total,
            "latency_avg_sec": avg_latency,
            "latency_samples_count": len(self._latencies),
        }

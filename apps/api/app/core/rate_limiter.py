"""Client IP rate limiting with trusted proxy handling."""

import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import Request

from app.core.config import settings


class ClientIPRateLimiter:
    """Sliding-window rate limiter keyed strictly by client IP address."""

    def __init__(self, requests_per_minute: int = 20):
        self.requests_per_minute = requests_per_minute
        self._history: Dict[str, List[float]] = defaultdict(list)

    def extract_client_ip(self, request: Request) -> str:
        """Extract authoritative client IP, trusting X-Forwarded-For only from configured trusted hosts."""
        client_host = request.client.host if request.client else "127.0.0.1"

        is_trusted = False
        if "*" in settings.trusted_hosts:
            is_trusted = True
        elif client_host in settings.trusted_hosts:
            is_trusted = True

        if is_trusted:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                # First IP in the list is the original client
                parts = [p.strip() for p in forwarded_for.split(",")]
                if parts and parts[0]:
                    return parts[0]

        return client_host

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request from client_ip is allowed under rate limit window (60s)."""
        now = time.time()
        window_start = now - 60.0

        # Prune older records
        history = self._history[client_ip]
        self._history[client_ip] = [ts for ts in history if ts > window_start]

        if len(self._history[client_ip]) >= self.requests_per_minute:
            return False

        self._history[client_ip].append(now)
        return True

    def reset(self) -> None:
        """Reset internal rate limit records."""
        self._history.clear()


ai_rate_limiter = ClientIPRateLimiter(requests_per_minute=settings.ai_rate_limit_rpm)

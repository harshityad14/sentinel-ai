"""Exponential backoff retry handler and error classification."""

import logging
import random
import time
from typing import Any, Callable, Optional, Tuple

logger = logging.getLogger("sentinel.streaming.retry")


def is_retryable_exception(exc: Exception) -> bool:
    """Classify whether an exception is transient (retryable) or permanent (non-retryable).
    
    Permanent non-retryable errors:
        - ValueError, TypeError, KeyError (schema/domain logical faults)
        - Malformed data / deserialization errors
    Retryable errors:
        - ConnectionError, TimeoutError, OSError, IOError, transient database deadlocks
    """
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return False
    if isinstance(exc, (ConnectionError, TimeoutError, OSError, IOError)):
        return True

    # Generic exception message inspection for transient broker/DB errors
    msg = str(exc).lower()
    if any(k in msg for k in ["timeout", "deadlock", "connection reset", "broken pipe", "temporarily unavailable"]):
        return True
    return False


class RetryHandler:
    """Manages retry loops with exponential backoff and randomized jitter."""

    def __init__(
        self,
        max_retries: int = 3,
        base_backoff_ms: int = 100,
        max_backoff_ms: int = 2000,
        initial_backoff_sec: Optional[float] = None,
        backoff_multiplier: float = 2.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        if initial_backoff_sec is not None:
            self.base_backoff_ms = int(initial_backoff_sec * 1000)
        else:
            self.base_backoff_ms = base_backoff_ms
        self.max_backoff_ms = max_backoff_ms
        self.backoff_multiplier = backoff_multiplier
        self.jitter = jitter

    def compute_backoff_seconds(self, attempt: int) -> float:
        """Compute exponential backoff interval in seconds for attempt (1-indexed)."""
        factor = self.backoff_multiplier ** (attempt - 1)
        backoff_ms = min(self.max_backoff_ms, self.base_backoff_ms * factor)
        if self.jitter:
            backoff_ms = backoff_ms * (0.8 + 0.4 * random.random())
        return max(0.001, backoff_ms / 1000.0)

    def execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute callable, retrying on retryable exceptions. Raises if retries exhausted."""
        success, result, _, last_exc = self.execute_with_retry(func, *args, **kwargs)
        if success:
            return result
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Operation failed without capturing exception")

    def execute_with_retry(
        self,
        func: Callable[..., Any],
        *args: Any,
        retryable_check: Callable[[Exception], bool] = is_retryable_exception,
        **kwargs: Any,
    ) -> Tuple[bool, Any, int, Optional[Exception]]:
        """Execute a callable with retry handling.
        
        Returns:
            Tuple[success: bool, result: Any, attempts: int, last_exception: Optional[Exception]]
        """
        attempts = 0
        last_exc: Optional[Exception] = None

        while attempts <= self.max_retries:
            attempts += 1
            try:
                result = func(*args, **kwargs)
                return True, result, attempts, None
            except Exception as exc:
                last_exc = exc
                if not retryable_check(exc) or attempts > self.max_retries:
                    logger.warning(f"Aborting execution after {attempts} attempts. Non-retryable or limit reached: {exc}")
                    break
                sleep_sec = self.compute_backoff_seconds(attempts)
                logger.info(f"Retryable error on attempt {attempts}/{self.max_retries}: {exc}. Backing off for {sleep_sec:.3f}s")
                time.sleep(sleep_sec)

        return False, None, attempts, last_exc

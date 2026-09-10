"""Idempotency and sliding-window event deduplication."""

import time
import uuid
from collections import OrderedDict
from typing import Optional


def generate_deterministic_event_id(upstream_event_id: str, stage_name: str) -> str:
    """Generate a deterministic derivative UUIDv5 based on upstream event ID and processing stage.
    
    Ensures that if an upstream message is replayed, the downstream derivative message
    generates the exact same event ID, enabling downstream deduplication.
    """
    namespace = uuid.NAMESPACE_OID
    seed = f"{upstream_event_id}:{stage_name}"
    return str(uuid.uuid5(namespace, seed))


class IdempotencyDeduplicator:
    """Sliding-window in-memory LRU deduplication cache for duplicate-event protection.
    
    Tracks recently processed event IDs and discards duplicate events within the TTL window.
    """

    def __init__(self, max_size: int = 50000, window_sec: float = 300.0):
        self.max_size = max_size
        self.window_sec = window_sec
        self._cache: OrderedDict[str, float] = OrderedDict()

    def is_duplicate(self, event_id: str, current_time: Optional[float] = None) -> bool:
        """Check if an event_id was already processed within the deduplication window."""
        now = current_time if current_time is not None else time.time()
        self._prune(now)
        return event_id in self._cache

    def record_processed(self, event_id: str, current_time: Optional[float] = None) -> None:
        """Register an event_id as processed in the deduplication cache."""
        now = current_time if current_time is not None else time.time()
        self._prune(now)
        self._cache[event_id] = now
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def check_and_record(self, event_id: str, current_time: Optional[float] = None) -> bool:
        """Check if event_id is duplicate; if not, records it. Returns True if duplicate."""
        if self.is_duplicate(event_id, current_time=current_time):
            return True
        self.record_processed(event_id, current_time=current_time)
        return False

    def _prune(self, now: float) -> None:
        """Prune expired items from the cache tail."""
        cutoff = now - self.window_sec
        while self._cache:
            _, ts = next(iter(self._cache.items()))
            if ts < cutoff:
                self._cache.popitem(last=False)
            else:
                break

    def clear(self) -> None:
        """Clear cache state."""
        self._cache.clear()

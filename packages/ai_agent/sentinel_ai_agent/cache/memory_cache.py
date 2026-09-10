"""Deterministic in-memory LRU cache for alert analysis and Q&A."""

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, TypeVar

from sentinel_models.ai_analyst import AlertAnalysisReport, AnalystQuestionResponse

T = TypeVar("T")


@dataclass
class CacheEntry:
    value: Any
    created_at: float
    expires_at: float


class DeterministicAnalysisCache:
    """Separate deterministic LRU caches for full incident analysis reports and conversational Q&A."""

    def __init__(self, max_entries: int = 1000, default_ttl_seconds: int = 3600):
        self.max_entries = max_entries
        self.default_ttl_seconds = default_ttl_seconds
        self._analysis_store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._qa_store: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def compute_evidence_signals_hash(alert: Any) -> str:
        """Compute a deterministic hash of alert evidence and contributing signals."""
        items: List[str] = []
        for ev in getattr(alert, "evidence", []):
            items.append(f"{ev.detector_name}:{ev.feature_name}:{ev.observed_value}:{ev.threshold_value}")
        for sig in getattr(alert, "contributing_signals", []):
            items.append(f"{sig.signal_id}:{sig.detector_name}:{sig.confidence}:{sig.severity}")
        raw = "|".join(sorted(items))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def compute_analysis_cache_key(
        cls,
        alert_id: str,
        last_seen_iso: str,
        status: str,
        evidence_signals_hash: str,
        prompt_version: str,
        model_name: str,
        mode: str = "comprehensive",
    ) -> str:
        """Compute a deterministic SHA-256 cache key for an alert analysis report."""
        raw = f"{alert_id}:{last_seen_iso}:{status}:{evidence_signals_hash}:{prompt_version}:{model_name}:{mode}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def compute_qa_cache_key(
        cls,
        alert_id: str,
        last_seen_iso: str,
        evidence_signals_hash: str,
        normalized_question: str,
        conversation_history_hash: str,
        prompt_version: str,
        model_name: str,
    ) -> str:
        """Compute a deterministic SHA-256 cache key for a Q&A answer."""
        raw = (
            f"{alert_id}:{last_seen_iso}:{evidence_signals_hash}:"
            f"{normalized_question.strip().lower()}:{conversation_history_hash}:{prompt_version}:{model_name}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_analysis(self, key: str) -> Optional[AlertAnalysisReport]:
        """Retrieve cached analysis report if present and not expired."""
        now = time.time()
        if key in self._analysis_store:
            entry = self._analysis_store[key]
            if now < entry.expires_at:
                self._analysis_store.move_to_end(key)
                self.hits += 1
                cached: AlertAnalysisReport = entry.value.model_copy()
                cached.cache_hit = True
                return cached
            else:
                del self._analysis_store[key]
        self.misses += 1
        return None

    def find_latest_analysis_for_alert(self, alert_id: str) -> Optional[AlertAnalysisReport]:
        """Find the most recent unexpired analysis report for an alert_id."""
        now = time.time()
        for key in reversed(list(self._analysis_store.keys())):
            entry = self._analysis_store[key]
            if entry.value.alert_id == alert_id:
                if now < entry.expires_at:
                    cached: AlertAnalysisReport = entry.value.model_copy()
                    cached.cache_hit = True
                    return cached
                else:
                    del self._analysis_store[key]
        return None

    def put_analysis(self, key: str, report: AlertAnalysisReport, ttl_seconds: Optional[int] = None) -> None:
        """Store an analysis report in cache with LRU eviction."""
        now = time.time()
        ttl = ttl_seconds or self.default_ttl_seconds
        if key in self._analysis_store:
            self._analysis_store.move_to_end(key)
        self._analysis_store[key] = CacheEntry(
            value=report.model_copy(),
            created_at=now,
            expires_at=now + ttl,
        )
        if len(self._analysis_store) > self.max_entries:
            self._analysis_store.popitem(last=False)

    def get_qa(self, key: str) -> Optional[AnalystQuestionResponse]:
        """Retrieve cached Q&A response if present and not expired."""
        now = time.time()
        if key in self._qa_store:
            entry = self._qa_store[key]
            if now < entry.expires_at:
                self._qa_store.move_to_end(key)
                self.hits += 1
                cached: AnalystQuestionResponse = entry.value.model_copy()
                cached.cache_hit = True
                return cached
            else:
                del self._qa_store[key]
        self.misses += 1
        return None

    def put_qa(self, key: str, response: AnalystQuestionResponse, ttl_seconds: Optional[int] = None) -> None:
        """Store a Q&A response in cache with LRU eviction."""
        now = time.time()
        ttl = ttl_seconds or self.default_ttl_seconds
        if key in self._qa_store:
            self._qa_store.move_to_end(key)
        self._qa_store[key] = CacheEntry(
            value=response.model_copy(),
            created_at=now,
            expires_at=now + ttl,
        )
        if len(self._qa_store) > self.max_entries:
            self._qa_store.popitem(last=False)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "analysis_entries": len(self._analysis_store),
            "qa_entries": len(self._qa_store),
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio": round(self.hits / max(1, self.hits + self.misses), 3),
        }

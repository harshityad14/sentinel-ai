"""Feature extraction abstractions.

Responsible for computing statistical features (SPLT, jitter, Shannon entropy, byte ratios)
without decrypting application payloads.
Full implementation belongs to Phase 2 (Feature Engineering & Telemetry).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from sentinel_models.events import FlowRecord


class BaseFeatureExtractor(ABC):
    """Abstract interface for extracting behavioral and statistical feature vectors."""

    @abstractmethod
    def extract_features(self, flow: FlowRecord) -> Dict[str, Any]:
        """Compute feature map from completed or in-flight flow record."""
        raise NotImplementedError("Feature extraction algorithms will be implemented in Phase 2.")

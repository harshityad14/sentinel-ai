"""Detection engine abstractions.

Architectural Rule:
Maintain clean separation between:
- rule-based detection
- statistical/anomaly detection
- supervised ML
- ensemble/correlation
- risk scoring

Full detection logic belongs to Phase 3 (Hybrid Threat Detection Engine)
and Phase 4 (Alert Correlation, Evidence & Risk Scoring).
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from sentinel_models.alerts import Alert
from sentinel_models.events import FlowRecord


class BaseDetector(ABC):
    """Abstract interface for modular threat analyzers."""

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Unique identifier of the detector."""
        raise NotImplementedError

    @property
    @abstractmethod
    def detection_type(self) -> str:
        """Category: rule | statistical | ml | correlation | scoring"""
        raise NotImplementedError

    @abstractmethod
    def analyze_flow(self, flow: FlowRecord) -> Optional[Alert]:
        """Evaluate a flow record and emit an Alert if threat thresholds are exceeded."""
        raise NotImplementedError("Threat detection logic will be implemented in Phase 3.")

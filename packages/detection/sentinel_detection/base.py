"""Abstract base detector interface for SentinelAI threat detection engine."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import uuid

from sentinel_models.detection import DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class BaseDetector(ABC):
    """Abstract interface for modular threat analyzers."""

    def __init__(self, enabled: bool = True, **config: Any) -> None:
        self.enabled = enabled
        self.config: Dict[str, Any] = config

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Unique identifier of the detector implementation."""
        raise NotImplementedError

    @property
    @abstractmethod
    def detector_type(self) -> DetectorType:
        """Category: RULE | STATISTICAL | ML | ENSEMBLE."""
        raise NotImplementedError

    @property
    @abstractmethod
    def threat_type(self) -> ThreatType:
        """Target threat category."""
        raise NotImplementedError

    @abstractmethod
    def detect(
        self,
        flow: FlowRecord,
        features: Optional[FeatureVector] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        """Analyze a flow and its feature vector.
        
        Returns:
            DetectionSignal if threat criteria are met, otherwise None.
        """
        raise NotImplementedError

    def _generate_signal_id(self) -> str:
        """Generate a unique identifier for emitted signals."""
        return f"sig_{self.detector_name}_{uuid.uuid4().hex[:8]}"

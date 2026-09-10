"""Canonical detection domain models for SentinelAI detection subsystem."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    BENIGN = "BENIGN"
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    PORT_SCAN = "PORT_SCAN"
    C2_BEACONING = "C2_BEACONING"
    DNS_DGA = "DNS_DGA"
    DNS_TUNNELING = "DNS_TUNNELING"
    SUSPICIOUS_TLS = "SUSPICIOUS_TLS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


class DetectorType(str, Enum):
    RULE = "RULE"
    STATISTICAL = "STATISTICAL"
    ML = "ML"
    ENSEMBLE = "ENSEMBLE"


class DetectionSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionEvidence(BaseModel):
    """Machine-readable evidence item traceable to an actual observed feature value."""
    feature_name: str = Field(..., description="Name of the triggering feature")
    observed_value: Any = Field(..., description="Actual value observed in the flow/features")
    threshold_value: Optional[Any] = Field(default=None, description="Configured rule or baseline threshold")
    description: str = Field(..., description="Human-readable explanation of why this is anomalous")


class DetectionSignal(BaseModel):
    """An individual detection signal produced by a single specialized detector."""
    signal_id: str = Field(..., description="Unique identifier of this signal")
    threat_type: ThreatType = Field(..., description="Classified threat category")
    detector_type: DetectorType = Field(..., description="Category: RULE, STATISTICAL, ML, ENSEMBLE")
    detector_name: str = Field(..., description="Name of the generating detector class")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Algorithmic confidence (0.0 to 1.0)")
    severity: DetectionSeverity = Field(..., description="Impact severity rating")
    evidence: List[DetectionEvidence] = Field(default_factory=list, description="Chain of evidence items")
    description: str = Field(..., description="Summary explanation of the finding")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary detector parameters")


class DetectionResult(BaseModel):
    """Correlated detection result representing the final output for a flow session."""
    detection_id: str = Field(..., description="Unique identifier of this detection result")
    flow_id: str = Field(..., description="Source FlowRecord identifier")
    threat_type: ThreatType = Field(default=ThreatType.BENIGN, description="Consensus threat classification")
    detector_type: DetectorType = Field(..., description="Primary or ensemble detector type")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Consensus confidence score")
    severity: DetectionSeverity = Field(default=DetectionSeverity.INFO, description="Consensus severity rating")
    evidence: List[DetectionEvidence] = Field(default_factory=list, description="Consolidated evidence items")
    signals: List[DetectionSignal] = Field(default_factory=list, description="Contributing individual signals")
    feature_version: str = Field(default="1.0", description="Feature schema version used")
    model_version: Optional[str] = Field(default=None, description="ML model version if ML contributed")
    detection_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when detection was concluded",
    )
    explanation: str = Field(default="Normal traffic flow", description="Human-readable incident summary")
    context: Dict[str, Any] = Field(default_factory=dict, description="Network context (IPs, ports, protocol)")

    @property
    def is_threat(self) -> bool:
        """True if classification is not BENIGN."""
        return self.threat_type != ThreatType.BENIGN

    def to_json(self) -> str:
        """Deterministic JSON output."""
        return self.model_dump_json(indent=2)

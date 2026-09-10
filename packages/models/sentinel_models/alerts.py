"""Standardized alert and incident domain models for SentinelAI."""

from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator


class AlertStatus(str, Enum):
    """Passive alert lifecycle operational states."""
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AlertSeverity(str, Enum):
    """Threat severity operational impact classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """Threat classification categories for high-level grouping and backward compatibility."""
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    C2_BEACONING = "C2_BEACONING"
    DNS_DGA_TUNNELING = "DNS_DGA_TUNNELING"
    SUSPICIOUS_ENCRYPTED_FLOW = "SUSPICIOUS_ENCRYPTED_FLOW"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


class AlertEntityType(str, Enum):
    """Network entity categorization."""
    IP = "IP"
    HOST = "HOST"
    SUBNET = "SUBNET"
    ENDPOINT = "ENDPOINT"


class AlertEntity(BaseModel):
    """Identified network subject or target involved in an incident."""
    entity_type: AlertEntityType = Field(default=AlertEntityType.IP, description="Entity type classification")
    identifier: str = Field(..., description="Unique entity identifier, e.g. IP address or hostname")
    ip_address: Optional[str] = Field(default=None, description="IPv4 or IPv6 address")
    port: Optional[int] = Field(default=None, description="Transport port associated with entity")
    role: Optional[str] = Field(default=None, description="Entity role: source, destination, attacker, target")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary entity context")


class MitreAttackRef(BaseModel):
    """Static local mapping to MITRE ATT&CK framework."""
    tactic: str = Field(..., description="MITRE Tactic name, e.g., Command and Control")
    tactic_id: str = Field(..., description="MITRE Tactic ID, e.g., TA0011")
    technique: str = Field(..., description="MITRE Technique name, e.g., Application Layer Protocol")
    technique_id: str = Field(..., description="MITRE Technique ID, e.g., T1071")
    subtechnique_id: Optional[str] = Field(default=None, description="MITRE Sub-technique ID, e.g., T1071.001")


class AlertEvidence(BaseModel):
    """Structured evidence item justifying the alert, traceable to actual features."""
    detector_name: str = Field(..., description="Specific detector module that generated the signal")
    detection_type: str = Field(default="rule", description="Detector category: rule | statistical | ml | ensemble")
    feature_name: Optional[str] = Field(default=None, description="Observed feature name")
    observed_value: Optional[Any] = Field(default=None, description="Actual observed feature value")
    threshold_value: Optional[Any] = Field(default=None, description="Configured rule or baseline threshold")
    confidence_contribution: float = Field(default=0.0, description="Detector confidence contribution (0.0 to 1.0)")
    correlation_reason: Optional[str] = Field(default=None, description="Reason this evidence was linked")
    description: Optional[str] = Field(default=None, description="Human-readable rationale")
    triggered_features: Dict[str, Any] = Field(default_factory=dict, description="Values that breached thresholds")
    raw_indicators: Dict[str, Any] = Field(default_factory=dict, description="Supporting telemetry values")


class AlertSignal(BaseModel):
    """Preserved copy of an individual contributing detection signal."""
    signal_id: str = Field(..., description="Unique signal identifier")
    flow_id: str = Field(..., description="Flow identifier associated with signal")
    threat_type: str = Field(..., description="Threat classification string")
    detector_type: str = Field(..., description="Detector category: RULE, STATISTICAL, ML, ENSEMBLE")
    detector_name: str = Field(..., description="Name of generating detector class")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence rating")
    severity: str = Field(..., description="Severity rating string")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Signal generation timestamp",
    )
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Machine-readable evidence items")
    description: str = Field(default="", description="Summary of finding")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary signal metadata")


class RiskScore(BaseModel):
    """Explainable multi-factor risk score."""
    score: int = Field(..., ge=0, le=100, description="Composite numeric risk score from 0 to 100")
    confidence_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence component (0.0 to 1.0)")
    severity_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Severity impact component (0.0 to 1.0)")
    agreement_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Detector agreement bonus (0.0 to 1.0)")
    signal_count_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Signal volume saturation (0.0 to 1.0)")
    recurrence_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Entity recurrence frequency factor")
    temporal_proximity_factor: float = Field(default=0.0, ge=0.0, le=1.0, description="Temporal clustering factor")
    breakdown: Dict[str, float] = Field(default_factory=dict, description="Weighted contribution of each factor")
    explanation: str = Field(default="", description="Human-readable risk justification")

    def __int__(self) -> int:
        return self.score

    def __float__(self) -> float:
        return float(self.score)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, RiskScore):
            return self.score == other.score
        if isinstance(other, (int, float)):
            return self.score == int(other)
        return False


class CorrelationGroup(BaseModel):
    """Cluster of related detections correlated across entity and temporal windows."""
    group_id: str = Field(..., description="Unique correlation group identifier")
    key: str = Field(..., description="Correlation partition key, e.g. entity_id or threat_class")
    correlation_type: str = Field(default="TEMPORAL_ENTITY", description="Correlation rule used")
    first_seen: datetime = Field(..., description="Timestamp of first event in group")
    last_seen: datetime = Field(..., description="Timestamp of most recent event in group")
    alert_ids: List[str] = Field(default_factory=list, description="IDs of alerts linked to this group")
    signal_count: int = Field(default=0, description="Total detection signals aggregated")
    entities: List[AlertEntity] = Field(default_factory=list, description="Entities involved in group")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary group tracking metadata")


class SecurityAlert(BaseModel):
    """Canonical security incident alert emitted by the SentinelAI correlation engine."""
    alert_id: str = Field(..., description="Unique deterministic or UUID alert identifier")
    timestamp: datetime = Field(..., description="Timestamp of alert generation")
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Earliest observed timestamp in incident",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Latest observed timestamp in incident",
    )
    flow_ids: List[str] = Field(default_factory=list, description="Associated network flow IDs")
    
    # Entity information
    source_entity: Optional[AlertEntity] = Field(default=None, description="Primary source entity")
    destination_entity: Optional[AlertEntity] = Field(default=None, description="Target entity")
    source_ip: str = Field(..., description="Threat source or compromised internal IP")
    destination_ip: Optional[str] = Field(default=None, description="Target host or external infrastructure")
    source_port: Optional[int] = Field(default=None)
    destination_port: Optional[int] = Field(default=None)
    protocol: Optional[str] = Field(default=None)
    
    # Threat classification
    threat_class: str = Field(default="UNKNOWN", description="Specific threat class, e.g. SYN_FLOOD, PORT_SCAN")
    category: Optional[Union[ThreatCategory, str]] = Field(default=None, description="High-level category grouping")
    
    # Strictly separated confidence, severity, and risk
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector consensus confidence (0.0 to 1.0)")
    severity: AlertSeverity = Field(..., description="Operational severity rating (LOW, MEDIUM, HIGH, CRITICAL)")
    risk_score: Union[RiskScore, int] = Field(..., description="Calculated 0-100 risk score or structured RiskScore")
    
    # Machine-readable evidence and contributing signals
    evidence: List[AlertEvidence] = Field(default_factory=list, description="Traceable machine-readable evidence items")
    contributing_signals: List[AlertSignal] = Field(default_factory=list, description="Raw contributing detection signals")
    correlation_group_id: Optional[str] = Field(default=None, description="Correlation group identifier")
    
    # Operational lifecycle
    status: AlertStatus = Field(default=AlertStatus.NEW, description="Alert lifecycle state: NEW, ACTIVE, ACKNOWLEDGED, RESOLVED")
    
    # Tracking and framework context
    detector_types: List[str] = Field(default_factory=list, description="Categories of detectors contributing to alert")
    feature_references: List[str] = Field(default_factory=list, description="Specific feature keys referenced in evidence")
    mitre_attack: Optional[MitreAttackRef] = Field(default=None, description="Static MITRE ATT&CK reference")
    explanation: str = Field(..., description="Human-readable plain English technical explanation")
    context: Dict[str, Any] = Field(default_factory=dict, description="Network and session context")
    remediation_playbook: Optional[str] = Field(default=None, description="Advisory remediation recommendations")
    related_flow_ids: List[str] = Field(default_factory=list, description="Backward compatibility alias for flow_ids")

    @model_validator(mode="before")
    @classmethod
    def sync_legacy_and_new_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync category and threat_class
            if "category" in data and "threat_class" not in data:
                cat = data["category"]
                data["threat_class"] = cat.value if isinstance(cat, Enum) else str(cat)
            elif "threat_class" in data and "category" not in data:
                tc = data["threat_class"]
                data["category"] = tc

            # Sync flow_ids and related_flow_ids
            if "related_flow_ids" in data and not data.get("flow_ids"):
                data["flow_ids"] = list(data["related_flow_ids"])
            elif "flow_ids" in data and not data.get("related_flow_ids"):
                data["related_flow_ids"] = list(data["flow_ids"])

            # Default first_seen and last_seen from timestamp
            ts = data.get("timestamp")
            if ts:
                if "first_seen" not in data:
                    data["first_seen"] = ts
                if "last_seen" not in data:
                    data["last_seen"] = ts

            # Auto-wrap numeric risk_score if an int was provided
            rs = data.get("risk_score")
            if isinstance(rs, int):
                data["risk_score"] = RiskScore(
                    score=rs,
                    explanation=f"Direct risk rating: {rs}/100",
                )
        return data

    @property
    def numeric_risk_score(self) -> int:
        """Return the integer risk score value whether stored as RiskScore or int."""
        if isinstance(self.risk_score, RiskScore):
            return self.risk_score.score
        return int(self.risk_score)

    def update_status(self, new_status: AlertStatus) -> None:
        """Passive internal alert lifecycle state transition."""
        self.status = new_status

    def to_json(self) -> str:
        """Stable deterministic JSON serialization."""
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "SecurityAlert":
        """Deserialize from JSON string."""
        return cls.model_validate_json(json_str)


# Backwards compatibility alias for Phase 0
Alert = SecurityAlert

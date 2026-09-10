"""Standardized alert and incident models for SentinelAI."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    C2_BEACONING = "C2_BEACONING"
    DNS_DGA_TUNNELING = "DNS_DGA_TUNNELING"
    SUSPICIOUS_ENCRYPTED_FLOW = "SUSPICIOUS_ENCRYPTED_FLOW"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitreAttackRef(BaseModel):
    """Mapping to standard MITRE ATT&CK framework."""
    tactic: str = Field(..., description="MITRE Tactic name, e.g., Command and Control")
    tactic_id: str = Field(..., description="MITRE Tactic ID, e.g., TA0011")
    technique: str = Field(..., description="MITRE Technique name, e.g., Application Layer Protocol")
    technique_id: str = Field(..., description="MITRE Technique ID, e.g., T1071")
    subtechnique_id: Optional[str] = Field(default=None, description="MITRE Sub-technique ID, e.g., T1071.001")


class AlertEvidence(BaseModel):
    """Structured evidence payload justifying the alert."""
    detector_name: str = Field(..., description="Specific detector module that generated the signal")
    detection_type: str = Field(..., description="rule | statistical | ml | correlation")
    triggered_features: Dict[str, Any] = Field(default_factory=dict, description="Values that breached thresholds")
    raw_indicators: Dict[str, Any] = Field(default_factory=dict, description="Supporting telemetry values")


class Alert(BaseModel):
    """Canonical alert entity emitted by SentinelAI detection engine."""
    alert_id: str = Field(..., description="Unique deterministic or UUID-based alert identifier")
    timestamp: datetime = Field(..., description="Timestamp of alert generation")
    category: ThreatCategory = Field(..., description="Threat classification category")
    severity: AlertSeverity = Field(..., description="Threat severity rating")
    
    # Statistical confidence and prioritized risk
    confidence: float = Field(..., ge=0.0, le=1.0, description="Algorithmic confidence score (0.0 to 1.0)")
    risk_score: int = Field(..., ge=0, le=100, description="Prioritized multi-factor risk score (0 to 100)")
    
    # Network entity identifiers
    source_ip: str = Field(..., description="Identified threat source or internal compromised host")
    destination_ip: Optional[str] = Field(default=None, description="Target host or external infrastructure")
    source_port: Optional[int] = Field(default=None)
    destination_port: Optional[int] = Field(default=None)
    protocol: Optional[str] = Field(default=None)
    
    # Context & Framework references
    mitre_attack: Optional[MitreAttackRef] = Field(default=None)
    evidence: List[AlertEvidence] = Field(default_factory=list, description="Chain of evidence supporting alert")
    explanation: str = Field(..., description="Human-readable plain English technical explanation")
    
    # Associated flow references
    related_flow_ids: List[str] = Field(default_factory=list, description="Associated flow IDs")
    
    # Advisory remediation (populated by GenAI Analyst in Phase 8)
    remediation_playbook: Optional[str] = Field(default=None, description="Advisory remediation recommendations")

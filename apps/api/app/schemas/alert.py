"""Security Alert API schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class AlertSignalRead(BaseModel):
    """Signal participating in an alert."""

    model_config = ConfigDict(from_attributes=True)

    detection_id: str = Field(description="Signal detection ID")
    flow_id: Optional[str] = Field(default=None, description="Related flow ID")
    threat_type: str = Field(description="Threat type")
    severity: str = Field(description="Signal severity")
    confidence: float = Field(description="Signal confidence")
    detector_type: str = Field(description="Originating detector")
    timestamp: datetime = Field(description="Detection timestamp")


class AlertEvidenceRead(BaseModel):
    """Evidence attached to an alert."""

    model_config = ConfigDict(from_attributes=True)

    evidence_type: str = Field(description="Type of evidence")
    description: str = Field(description="Evidence narrative")
    raw_values: Optional[Dict[str, Any]] = Field(default=None, description="Evidence metrics")
    confidence: float = Field(description="Evidence confidence score")
    weight: float = Field(description="Contribution weight")


class AlertEntityRead(BaseModel):
    """Entity involved in an alert."""

    model_config = ConfigDict(from_attributes=True)

    entity_type: str = Field(description="Entity type (e.g. IP_ADDRESS, DOMAIN, HOST)")
    identifier: str = Field(description="Entity value")
    role: str = Field(description="Role in the incident (e.g. SOURCE, DESTINATION)")
    confidence: float = Field(description="Attribution confidence")


class AlertLifecycleHistoryRead(BaseModel):
    """Audit entry for alert state transitions."""

    model_config = ConfigDict(from_attributes=True)

    previous_status: str = Field(description="Previous status")
    new_status: str = Field(description="New status")
    changed_at: datetime = Field(description="Timestamp of change")
    changed_by: str = Field(description="Actor or analyst who triggered the transition")
    notes: Optional[str] = Field(default=None, description="Analyst rationale or resolution notes")


class SecurityAlertRead(BaseModel):
    """Full security alert response schema."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: str = Field(description="Unique alert identifier")
    correlation_group_id: Optional[str] = Field(default=None, description="Associated correlation group ID")
    threat_class: str = Field(description="Threat classification")
    severity: str = Field(description="Severity tier (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
    status: str = Field(description="Lifecycle status (NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE)")
    confidence: float = Field(description="Overall alert confidence [0.0 - 1.0]")
    risk_score: float = Field(description="Calculated risk score [0.0 - 100.0]")
    risk_level: str = Field(description="Risk level tier")
    risk_breakdown: Optional[Dict[str, Any]] = Field(default=None, description="Breakdown of risk contributors")
    mitre_attack: Optional[List[Dict[str, Any]]] = Field(default=None, description="Mapped MITRE ATT&CK techniques")
    title: str = Field(description="Human-readable alert title")
    description: Optional[str] = Field(default=None, description="Detailed alert summary")
    explanation: Optional[str] = Field(default=None, description="Detection rationale")
    flow_ids: Optional[List[str]] = Field(default=None, description="Referenced flow IDs")
    first_seen: datetime = Field(description="Timestamp when earliest signal occurred")
    last_seen: datetime = Field(description="Timestamp when latest signal occurred")
    created_at: datetime = Field(description="Alert creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")

    signals: List[AlertSignalRead] = Field(default_factory=list, description="Detection signals")
    evidence_items: List[AlertEvidenceRead] = Field(default_factory=list, description="Corroborating evidence")
    entities: List[AlertEntityRead] = Field(default_factory=list, description="Involved entities")
    lifecycle_history: List[AlertLifecycleHistoryRead] = Field(default_factory=list, description="Internal state transition history")


class AlertAcknowledgeRequest(BaseModel):
    """Request payload to acknowledge an alert."""

    changed_by: str = Field(default="analyst", description="Identifier of the analyst acknowledging")
    notes: Optional[str] = Field(default=None, description="Optional triage notes")


class AlertResolveRequest(BaseModel):
    """Request payload to resolve an alert."""

    changed_by: str = Field(default="analyst", description="Identifier of the analyst resolving")
    notes: Optional[str] = Field(default=None, description="Resolution rationale or summary")


class AlertStatisticsRead(BaseModel):
    """Aggregated alert metrics for dashboard summaries."""

    total_alerts: int = Field(description="Total alert count")
    average_risk_score: float = Field(description="Average risk score across all alerts")
    by_status: Dict[str, int] = Field(description="Alert counts by lifecycle status")
    by_severity: Dict[str, int] = Field(description="Alert counts by severity tier")
    by_threat_class: Dict[str, int] = Field(description="Alert counts by threat class")

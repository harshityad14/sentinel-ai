"""Statistics and Telemetry API schemas."""

from typing import List, Dict, Any
from pydantic import BaseModel, Field


class ThreatDistributionItem(BaseModel):
    """Distribution entry for threat types."""

    threat_type: str = Field(description="Threat classification")
    count: int = Field(description="Frequency count")


class EntityStatisticsItem(BaseModel):
    """Entity activity metrics."""

    identifier: str = Field(description="IP, domain, or host identifier")
    entity_type: str = Field(description="Entity type")
    alert_count: int = Field(description="Number of alerts involving this entity")


class TelemetrySummaryRead(BaseModel):
    """Overview telemetry metrics."""

    total_flows: int = Field(description="Total recorded flows")
    total_detections: int = Field(description="Total threat detections")
    total_alerts: int = Field(description="Total correlated alerts")
    threat_distribution: List[ThreatDistributionItem] = Field(description="Detected threats breakdown")
    top_entities: List[EntityStatisticsItem] = Field(description="Top anomalous entities")


class ProcessingStatusRead(BaseModel):
    """Pipeline and ingestion status overview."""

    pipeline_status: str = Field(default="PASSIVE_INGESTION_ACTIVE", description="Ingestion pipeline state")
    passive_mode_active: bool = Field(default=True, description="Passive packet monitoring invariant confirmation")
    total_flows_processed: int = Field(description="Total flows tracked")
    total_detections_generated: int = Field(description="Total detections produced")
    total_alerts_persisted: int = Field(description="Total alerts in store")

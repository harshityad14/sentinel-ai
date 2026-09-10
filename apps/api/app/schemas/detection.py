"""Detection API schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class DetectionEvidenceRead(BaseModel):
    """Detection evidence item response schema."""

    model_config = ConfigDict(from_attributes=True)

    feature_name: str = Field(description="Name of the feature providing evidence")
    observed_value: float = Field(description="Observed value")
    threshold: Optional[float] = Field(default=None, description="Detection threshold")
    score: float = Field(description="Evidence anomaly score")
    contribution: float = Field(description="Contribution weight")
    description: Optional[str] = Field(default=None, description="Human-readable explanation")


class DetectionRead(BaseModel):
    """Detection result response schema."""

    model_config = ConfigDict(from_attributes=True)

    detection_id: str = Field(description="Unique detection ID")
    flow_id: str = Field(description="Associated flow ID")
    threat_type: str = Field(description="Detected threat class")
    severity: str = Field(description="Severity tier")
    confidence: float = Field(description="Model or rule confidence [0.0 - 1.0]")
    is_threat: bool = Field(description="Whether classified as positive threat")
    detector_name: str = Field(description="Identifier of detecting engine")
    explanation: Optional[str] = Field(default=None, description="Reasoning text")
    timestamp: datetime = Field(description="Detection event timestamp")
    evidence_items: List[DetectionEvidenceRead] = Field(default_factory=list, description="Supporting evidence items")

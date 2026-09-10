"""Pydantic API schemas for AI analyst endpoints."""

from typing import Any, Dict
from pydantic import BaseModel, Field

from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionRequest,
    AnalystQuestionResponse,
    AttackStageAnalysis,
    AuditableValidationLog,
    EvidenceCitation,
    GroundingStatus,
    InvestigationStep,
    UncertaintyIndicator,
)


class AIHealthResponse(BaseModel):
    """Health and status of the GenAI Security Analyst service."""
    status: str = Field(default="healthy")
    provider: Dict[str, Any] = Field(default_factory=dict)
    cache: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "AlertAnalysisReport",
    "AnalystQuestionRequest",
    "AnalystQuestionResponse",
    "AttackStageAnalysis",
    "AuditableValidationLog",
    "EvidenceCitation",
    "GroundingStatus",
    "InvestigationStep",
    "UncertaintyIndicator",
    "AIHealthResponse",
]

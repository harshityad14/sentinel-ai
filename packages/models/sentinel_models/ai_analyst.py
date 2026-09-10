"""Canonical domain models for the SentinelAI advisory GenAI Security Analyst."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GroundingStatus(str, Enum):
    """Validation outcome for evidence grounding check."""
    PASSED = "PASSED"
    FLAGGED_UNGROUNDED = "FLAGGED_UNGROUNDED"


class EvidenceCitation(BaseModel):
    """Direct reference to a verified telemetry evidence item."""
    citation_id: str = Field(..., description="Unique citation key, e.g. EVID-1")
    detector_name: str = Field(..., description="Detector module that produced this evidence")
    feature_name: Optional[str] = Field(default=None, description="Feature referenced")
    observed_value: Any = Field(..., description="Observed value in telemetry")
    threshold_value: Optional[Any] = Field(default=None, description="Configured rule or baseline threshold")
    relevance: str = Field(..., description="Technical justification for why this evidence supports the finding")


class AttackStageAnalysis(BaseModel):
    """Attack lifecycle and kill-chain phase estimation."""
    stage_name: str = Field(..., description="Stage name (e.g. Reconnaissance, C2, Exfiltration)")
    kill_chain_phase: str = Field(..., description="Lockheed Martin Kill Chain phase")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Stage attribution confidence")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence justifying this stage")


class InvestigationStep(BaseModel):
    """Actionable, manual SOC investigation task (strictly manual checks, no operational commands)."""
    step_number: int = Field(..., ge=1, description="Sequential investigation order")
    priority: str = Field(..., description="Priority: HIGH, MEDIUM, LOW")
    action: str = Field(..., description="Specific investigation activity to perform manually")
    target_entity: str = Field(..., description="IP, hostname, or domain to inspect")
    rationale: str = Field(..., description="Forensic rationale for this investigation step")


class UncertaintyIndicator(BaseModel):
    """Explicit declaration of data gaps, ambiguous indicators, or unverified claims."""
    aspect: str = Field(..., description="Uncertain finding or unverified aspect")
    reason: str = Field(..., description="Why evidence is incomplete or unverified")
    recommended_telemetry: Optional[str] = Field(
        default=None,
        description="Passive telemetry that would resolve ambiguity (strictly passive records)",
    )


class AuditableValidationLog(BaseModel):
    """Auditable log of grounding verification outcomes across authoritative entities."""
    total_entities_checked: int = Field(default=0, description="Total entities verified against source telemetry")
    verified_entities_count: int = Field(default=0, description="Count of entities matched in source telemetry")
    unsupported_entities: List[str] = Field(default_factory=list, description="List of ungrounded entities detected")
    validation_status: GroundingStatus = Field(default=GroundingStatus.PASSED, description="Validation status")


class AlertAnalysisReport(BaseModel):
    """Canonical, fully validated advisory incident report emitted by the GenAI Security Analyst."""
    analysis_id: str = Field(..., description="Unique analysis report UUID")
    alert_id: str = Field(..., description="Target SecurityAlert ID")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of report generation",
    )
    model_identifier: str = Field(..., description="Model and provider name used")
    
    # Executive overview
    executive_summary: str = Field(..., description="High-level 2-3 sentence executive incident summary")
    observed_facts: List[str] = Field(..., description="Verified factual statements directly derived from telemetry")
    
    # Deep dive & threat reasoning (strictly demarcated as model inference)
    threat_assessment: str = Field(..., description="Technical assessment of the threat behavior")
    threat_reasoning: str = Field(..., description="Analytical deduction explaining attacker mechanism")
    risk_interpretation: str = Field(..., description="Explanation of composite risk score factor contributions")
    
    # Grounded references & frameworks
    evidence_citations: List[EvidenceCitation] = Field(default_factory=list, description="Citations to verified evidence")
    attack_stage: AttackStageAnalysis = Field(..., description="Estimated attack lifecycle stage")
    mitre_explanation: str = Field(..., description="Contextual explanation of MITRE ATT&CK technique")
    
    # Actions & False Positive analysis
    false_positive_analysis: str = Field(..., description="Assessment of plausible benign explanations")
    recommended_investigation_steps: List[InvestigationStep] = Field(
        default_factory=list,
        description="Ordered list of manual investigation steps (strictly no operational commands)",
    )
    uncertainties: List[UncertaintyIndicator] = Field(
        default_factory=list,
        description="Explicit declarations of incomplete evidence or unverified areas",
    )
    
    # Metadata & Auditing
    is_fallback: bool = Field(default=False, description="True if generated via deterministic local fallback")
    fallback_reason: Optional[str] = Field(default=None, description="Reason local fallback was triggered")
    cache_hit: bool = Field(default=False, description="True if served from analysis cache")
    validation_log: AuditableValidationLog = Field(
        default_factory=AuditableValidationLog,
        description="Auditable grounding validation results",
    )


class AnalystQuestionRequest(BaseModel):
    """Structured question posed by a SOC analyst regarding a specific alert."""
    question: str = Field(..., min_length=3, max_length=500, description="Analyst question (max 500 characters)")
    conversation_history: List[Dict[str, str]] = Field(
        default_factory=list,
        max_length=6,
        description="Recent conversation turns [role, content]",
    )


class AnalystQuestionResponse(BaseModel):
    """Grounded answer to analyst inquiry."""
    alert_id: str = Field(..., description="Target alert ID")
    question: str = Field(..., description="Analyst question")
    answer: str = Field(..., description="Grounded response")
    evidence_citations: List[EvidenceCitation] = Field(default_factory=list, description="Supporting citations")
    grounded_in_telemetry: bool = Field(default=True, description="Whether answer is grounded in telemetry")
    uncertainty_notes: Optional[str] = Field(default=None, description="Notes on telemetry gaps or ambiguity")
    cache_hit: bool = Field(default=False, description="True if served from cache")

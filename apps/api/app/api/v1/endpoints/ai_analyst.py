"""API endpoints for the SentinelAI GenAI Security Analyst."""

import logging
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limiter import ai_rate_limiter
from app.db.session import get_db
from app.models.alert import SecurityAlertModel
from app.schemas.ai_analyst import (
    AIHealthResponse,
    AlertAnalysisReport,
    AnalystQuestionRequest,
    AnalystQuestionResponse,
)
from app.services.alert_service import AlertService
from app.services.flow_service import FlowService
from sentinel_ai_agent.config import AIAnalystConfig
from sentinel_ai_agent.service import GenAIAnalystService
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    MitreAttackRef,
    RiskScore,
    SecurityAlert,
)
from sentinel_models.events import FlowRecord, ProtocolType

logger = logging.getLogger("sentinel.api.ai_analyst")

router = APIRouter(tags=["AI Security Analyst"])

_ai_service_instance: Optional[GenAIAnalystService] = None


def get_ai_service() -> GenAIAnalystService:
    """Dependency provider returning singleton GenAIAnalystService instance."""
    global _ai_service_instance
    if _ai_service_instance is None:
        config = AIAnalystConfig(
            provider=settings.ai_provider,
            model_name=settings.ai_model,
            api_key=settings.ai_api_key,
            base_url=settings.ai_base_url,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            rate_limit_rpm=settings.ai_rate_limit_rpm,
            cache_ttl_seconds=settings.ai_cache_ttl_seconds,
            cache_max_entries=settings.ai_cache_max_entries,
        )
        _ai_service_instance = GenAIAnalystService(config=config)
    return _ai_service_instance


def to_domain_alert(db_alert: SecurityAlertModel) -> SecurityAlert:
    """Convert relational SecurityAlertModel to canonical SecurityAlert domain model."""
    source_ip = "127.0.0.1"
    destination_ip = None
    for ent in db_alert.entities:
        if ent.role == "SOURCE":
            source_ip = ent.identifier
        elif ent.role == "DESTINATION":
            destination_ip = ent.identifier

    evidence: List[AlertEvidence] = []
    for ev in db_alert.evidence_items:
        evidence.append(
            AlertEvidence(
                detector_name=ev.evidence_type or "detector",
                detection_type="statistical" if "stat" in (ev.evidence_type or "").lower() else "rule",
                feature_name=ev.evidence_type,
                observed_value=ev.raw_values.get("observed_value") if ev.raw_values else None,
                threshold_value=ev.raw_values.get("threshold_value") if ev.raw_values else None,
                confidence_contribution=ev.weight if ev.weight is not None else 1.0,
                description=ev.description,
                triggered_features=ev.raw_values or {},
            )
        )

    signals: List[AlertSignal] = []
    for sig in db_alert.signals:
        signals.append(
            AlertSignal(
                signal_id=sig.detection_id,
                flow_id=sig.flow_id or "",
                threat_type=sig.threat_type,
                detector_type=sig.detector_type,
                detector_name=sig.detector_type,
                confidence=sig.confidence,
                severity=sig.severity,
                timestamp=sig.timestamp,
            )
        )

    mitre_ref: Optional[MitreAttackRef] = None
    if db_alert.mitre_attack:
        if isinstance(db_alert.mitre_attack, list) and db_alert.mitre_attack:
            m = db_alert.mitre_attack[0]
            mitre_ref = MitreAttackRef(
                tactic=m.get("tactic", "Unknown"),
                tactic_id=m.get("tactic_id", "TA0000"),
                technique=m.get("technique", "Unknown"),
                technique_id=m.get("technique_id", "T0000"),
                subtechnique_id=m.get("subtechnique_id"),
            )
        elif isinstance(db_alert.mitre_attack, dict):
            m = db_alert.mitre_attack
            mitre_ref = MitreAttackRef(
                tactic=m.get("tactic", "Unknown"),
                tactic_id=m.get("tactic_id", "TA0000"),
                technique=m.get("technique", "Unknown"),
                technique_id=m.get("technique_id", "T0000"),
                subtechnique_id=m.get("subtechnique_id"),
            )

    severity_enum = (
        AlertSeverity(db_alert.severity)
        if db_alert.severity in AlertSeverity.__members__
        else AlertSeverity.HIGH
    )
    status_enum = (
        AlertStatus(db_alert.status)
        if db_alert.status in AlertStatus.__members__
        else AlertStatus.NEW
    )

    return SecurityAlert(
        alert_id=db_alert.alert_id,
        timestamp=db_alert.created_at,
        first_seen=db_alert.first_seen,
        last_seen=db_alert.last_seen,
        flow_ids=db_alert.flow_ids or [],
        source_ip=source_ip,
        destination_ip=destination_ip,
        threat_class=db_alert.threat_class,
        confidence=db_alert.confidence,
        severity=severity_enum,
        risk_score=RiskScore(score=int(db_alert.risk_score), explanation=db_alert.explanation or ""),
        status=status_enum,
        evidence=evidence,
        contributing_signals=signals,
        mitre_attack=mitre_ref,
        explanation=db_alert.explanation or db_alert.title,
    )


@router.post(
    "/alerts/{alert_id}/analyze",
    response_model=AlertAnalysisReport,
    summary="Generate grounded AI analysis report for an alert",
)
async def analyze_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    ai_service: GenAIAnalystService = Depends(get_ai_service),
):
    """Generate or retrieve a cached grounded AI security analysis report for the specified alert.
    
    INVARIANTS:
    - Advisory only; zero outbound packets or automated remediation.
    - Remote LLM failure returns HTTP 200 with is_fallback=True.
    - HTTP 503 is returned strictly if both remote and local fallback generation fail.
    - Cache hits return instantly and bypass rate-limiting quotas.
    """
    alert_service = AlertService(db)
    db_alert = alert_service.get_alert_by_id(alert_id)
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )

    domain_alert = to_domain_alert(db_alert)

    # 1. Check cache first (cache hits bypass rate limiting)
    last_seen_iso = domain_alert.last_seen.isoformat() if domain_alert.last_seen else "unknown"
    status_str = domain_alert.status.value if hasattr(domain_alert.status, "value") else str(domain_alert.status)
    evidence_hash = ai_service.cache.compute_evidence_signals_hash(domain_alert)

    cache_key = ai_service.cache.compute_analysis_cache_key(
        alert_id=domain_alert.alert_id,
        last_seen_iso=last_seen_iso,
        status=status_str,
        evidence_signals_hash=evidence_hash,
        prompt_version=ai_service.config.prompt_version,
        model_name=ai_service.config.model_name,
        mode="comprehensive",
    )

    cached_report = ai_service.get_cached_analysis_by_key(cache_key)
    if cached_report:
        return cached_report

    # 2. Cache miss -> Enforce client IP rate limit
    client_ip = ai_rate_limiter.extract_client_ip(request)
    if not ai_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for AI analyst requests (max 20 requests/minute).",
        )

    # 3. Retrieve associated flow records if present
    flow_service = FlowService(db)
    flow_records: List[FlowRecord] = []
    if domain_alert.flow_ids:
        for fid in domain_alert.flow_ids[:10]:
            fl = flow_service.get_flow_by_id(fid)
            if fl:
                try:
                    proto_enum = (
                        ProtocolType(fl.protocol.upper())
                        if hasattr(fl, "protocol") and fl.protocol and fl.protocol.upper() in ProtocolType.__members__
                        else ProtocolType.TCP
                    )
                    flow_records.append(
                        FlowRecord(
                            flow_id=fl.flow_id,
                            start_time=fl.start_time,
                            end_time=fl.end_time,
                            duration_sec=fl.duration_sec,
                            source_ip=fl.src_ip,
                            destination_ip=fl.dst_ip,
                            source_port=fl.src_port,
                            destination_port=fl.dst_port,
                            protocol=proto_enum,
                            total_packets=fl.packet_count,
                            total_bytes=fl.byte_count,
                            tcp_flags=fl.tcp_flags or {},
                        )
                    )
                except Exception as ex:
                    logger.debug("Could not map flow %s: %s", fid, ex)

    # 4. Generate analysis report
    try:
        report = await ai_service.analyze_alert(domain_alert, flows=flow_records)
        return report
    except Exception as e:
        logger.error("Total failure generating analysis for alert %s: %s", alert_id, e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AI Analyst service temporarily unavailable: {e}",
        )


@router.get(
    "/alerts/{alert_id}/analysis",
    response_model=AlertAnalysisReport,
    summary="Retrieve latest cached analysis report for an alert",
)
def get_cached_analysis(
    alert_id: str,
    db: Session = Depends(get_db),
    ai_service: GenAIAnalystService = Depends(get_ai_service),
):
    """Fetch the latest cached analysis report for an alert without re-triggering generation."""
    cached = ai_service.cache.find_latest_analysis_for_alert(alert_id)
    if not cached:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis report found for alert '{alert_id}'. Please trigger analysis first.",
        )
    return cached


@router.post(
    "/alerts/{alert_id}/ask",
    response_model=AnalystQuestionResponse,
    summary="Submit an analyst question regarding an alert",
)
async def ask_question_about_alert(
    alert_id: str,
    payload: AnalystQuestionRequest,
    request: Request,
    db: Session = Depends(get_db),
    ai_service: GenAIAnalystService = Depends(get_ai_service),
):
    """Answer an analyst inquiry grounded strictly in the alert's telemetry.
    
    INVARIANTS:
    - Question length bounded [3, 500].
    - Zero active network probing or execution.
    - Rate limit enforced by client IP on cache misses.
    """
    cleaned_q = payload.question.strip()
    if len(cleaned_q) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Question is too short (minimum 3 characters required).",
        )
    if len(payload.question) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Question exceeds maximum allowed length of 500 characters.",
        )

    alert_service = AlertService(db)
    db_alert = alert_service.get_alert_by_id(alert_id)
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )

    domain_alert = to_domain_alert(db_alert)

    # 1. Check rate limit
    client_ip = ai_rate_limiter.extract_client_ip(request)
    if not ai_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for AI analyst requests (max 20 requests/minute).",
        )

    try:
        response = await ai_service.ask_question(
            alert=domain_alert,
            question=payload.question,
            conversation_history=payload.conversation_history,
        )
        return response
    except Exception as e:
        logger.error("Error answering question for alert %s: %s", alert_id, e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AI Analyst service temporarily unavailable: {e}",
        )


@router.get(
    "/ai/health",
    response_model=AIHealthResponse,
    summary="Get GenAI Security Analyst service health and operational metrics",
)
async def ai_health(
    ai_service: GenAIAnalystService = Depends(get_ai_service),
):
    """Retrieve operational health, provider configuration, cache statistics, and request counts."""
    health_data = await ai_service.check_health()
    return AIHealthResponse(**health_data)

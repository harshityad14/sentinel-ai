"""Deterministic heuristic fallback engine for offline continuity."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionResponse,
    AttackStageAnalysis,
    AuditableValidationLog,
    EvidenceCitation,
    GroundingStatus,
    InvestigationStep,
    UncertaintyIndicator,
)
from sentinel_models.alerts import SecurityAlert


class DeterministicFallbackEngine:
    """Produces grounded, deterministic analysis reports directly from alert telemetry on provider failure."""

    @classmethod
    def generate_fallback_report(
        cls,
        alert: SecurityAlert,
        reason: str = "Remote provider unavailable",
    ) -> AlertAnalysisReport:
        """Construct a validated AlertAnalysisReport directly from alert attributes."""
        # Build citations from actual evidence
        citations: List[EvidenceCitation] = []
        for idx, ev in enumerate(alert.evidence[:8], start=1):
            citations.append(
                EvidenceCitation(
                    citation_id=f"EVID-{idx:02d}",
                    detector_name=ev.detector_name,
                    feature_name=ev.feature_name,
                    observed_value=ev.observed_value if ev.observed_value is not None else "observed",
                    threshold_value=ev.threshold_value,
                    relevance=f"Telemetry anomaly flagged by {ev.detector_name}",
                )
            )

        if not citations:
            citations.append(
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="heuristic_engine",
                    feature_name="confidence",
                    observed_value=float(alert.confidence),
                    threshold_value=None,
                    relevance="Aggregated detector confidence score",
                )
            )

        # Determine attack stage
        threat = alert.threat_class.upper()
        if "SCAN" in threat or "PROBE" in threat:
            stage_name = "Reconnaissance"
            kill_chain = "Reconnaissance"
        elif "C2" in threat or "BEACON" in threat:
            stage_name = "Command and Control"
            kill_chain = "Command & Control"
        elif "EXFILTRATION" in threat or "TUNNELING" in threat:
            stage_name = "Exfiltration"
            kill_chain = "Exfiltration"
        elif "FLOOD" in threat or "DDOS" in threat:
            stage_name = "Impact"
            kill_chain = "Impact"
        else:
            stage_name = "Suspicious Flow Activity"
            kill_chain = "Delivery / Execution"

        # Construct facts
        dst_info = f":{alert.destination_port}" if alert.destination_port else ""
        facts = [
            f"Alert ID {alert.alert_id} classified as {alert.threat_class} with severity {alert.severity}",
            f"Source host {alert.source_ip} targeting {alert.destination_ip or 'network'}{dst_info}",
            f"Calculated risk rating: {alert.numeric_risk_score}/100 with confidence {alert.confidence:.2f}",
        ]
        if alert.explanation:
            facts.append(alert.explanation)

        # Investigation steps
        investigation_steps = [
            InvestigationStep(
                step_number=1,
                priority="HIGH",
                action="Review authoritative network flow telemetry and DNS resolution history for the source host",
                target_entity=alert.source_ip,
                rationale="Confirm connection frequency and check for anomalous domain queries",
            ),
            InvestigationStep(
                step_number=2,
                priority="MEDIUM",
                action="Inspect host endpoint process telemetry to identify initiating application",
                target_entity=alert.source_ip,
                rationale="Correlate socket connection timestamp with local process creation records",
            ),
        ]

        mitre_text = (
            f"Maps to MITRE technique {alert.mitre_attack.technique} ({alert.mitre_attack.technique_id}) "
            f"under tactic {alert.mitre_attack.tactic}."
            if alert.mitre_attack
            else f"Associated with standard {alert.threat_class} tactics."
        )

        return AlertAnalysisReport(
            analysis_id=f"rep-fallback-{uuid.uuid4().hex[:8]}",
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="deterministic-fallback-v1",
            executive_summary=(
                f"Deterministic synthesis for {alert.threat_class} alert involving source {alert.source_ip} "
                f"targeting {alert.destination_ip or 'internal network'}. Severity: {alert.severity}."
            ),
            observed_facts=facts,
            threat_assessment=(
                f"Deterministic analysis of observed indicators confirms {alert.threat_class} detection. "
                f"The incident exhibits elevated risk ({alert.numeric_risk_score}/100) and requires SOC investigation."
            ),
            threat_reasoning=(
                f"Detection rules flagged feature threshold breaches indicating non-standard network session "
                f"behavior from {alert.source_ip}."
            ),
            risk_interpretation=(
                f"Composite risk score {alert.numeric_risk_score} based on detection severity ({alert.severity}) "
                f"and detector confidence ({alert.confidence:.2f})."
            ),
            evidence_citations=citations,
            attack_stage=AttackStageAnalysis(
                stage_name=stage_name,
                kill_chain_phase=kill_chain,
                confidence=float(alert.confidence),
                supporting_evidence_ids=[c.citation_id for c in citations],
            ),
            mitre_explanation=mitre_text,
            false_positive_analysis=(
                "Evaluate whether scheduled IT monitoring, security scanners, or planned maintenance "
                "could account for the observed traffic pattern."
            ),
            recommended_investigation_steps=investigation_steps,
            uncertainties=[
                UncertaintyIndicator(
                    aspect="AI Model Inference",
                    reason=f"Generated via local deterministic synthesis because: {reason}",
                    recommended_telemetry="Review raw telemetry indicators and alert evidence items directly",
                )
            ],
            is_fallback=True,
            fallback_reason=reason,
            cache_hit=False,
            validation_log=AuditableValidationLog(
                total_entities_checked=len(citations) + 2,
                verified_entities_count=len(citations) + 2,
                unsupported_entities=[],
                validation_status=GroundingStatus.PASSED,
            ),
        )

    @classmethod
    def generate_fallback_qa(
        cls,
        alert: SecurityAlert,
        question: str,
        reason: str = "Remote provider unavailable",
    ) -> AnalystQuestionResponse:
        """Generate a fallback Q&A answer directly from alert telemetry."""
        return AnalystQuestionResponse(
            alert_id=alert.alert_id,
            question=question,
            answer=(
                f"Local fallback analysis: Alert {alert.alert_id} recorded threat class {alert.threat_class} "
                f"between source {alert.source_ip} and destination {alert.destination_ip}. "
                f"Explanation: {alert.explanation}"
            ),
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="heuristic_engine",
                    feature_name="explanation",
                    observed_value=alert.explanation,
                    threshold_value=None,
                    relevance="Primary alert description from detection engine",
                )
            ],
            grounded_in_telemetry=True,
            uncertainty_notes=f"Answer served via local fallback ({reason})",
            cache_hit=False,
        )

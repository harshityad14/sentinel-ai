"""Deterministic Mock LLM Provider for offline development and zero-cost testing."""

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type, TypeVar

from sentinel_ai_agent.providers.base import BaseLLMProvider
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

T = TypeVar("T")


class MockLLMProvider(BaseLLMProvider):
    """Deterministic, offline LLM provider for CI/CD and unit testing."""

    def __init__(
        self,
        model_name: str = "mock-analyst-v1",
        should_fail: bool = False,
        should_timeout: bool = False,
        simulated_latency: float = 0.001,
        custom_report: Optional[AlertAnalysisReport] = None,
        custom_response: Optional[AnalystQuestionResponse] = None,
    ):
        self.model_name = model_name
        self.should_fail = should_fail
        self.should_timeout = should_timeout
        self.simulated_latency = simulated_latency
        self.custom_report = custom_report
        self.custom_response = custom_response
        self.invocation_count = 0

    async def generate_structured(
        self,
        prompt: str,
        system_prompt: str,
        response_schema: Type[T],
        temperature: float = 0.0,
        max_tokens: int = 1000,
        timeout_seconds: float = 15.0,
    ) -> T:
        self.invocation_count += 1

        if self.should_timeout:
            await asyncio.sleep(timeout_seconds + 0.1)
            raise TimeoutError("Mock LLM call simulated timeout")

        if self.simulated_latency > 0:
            await asyncio.sleep(self.simulated_latency)

        if self.should_fail:
            raise RuntimeError("Mock LLM provider simulated failure")

        if response_schema is AlertAnalysisReport:
            if self.custom_report:
                return self.custom_report  # type: ignore

            return self._synthesize_alert_report(prompt)  # type: ignore

        if response_schema is AnalystQuestionResponse:
            if self.custom_response:
                return self.custom_response  # type: ignore

            return self._synthesize_qa_response(prompt)  # type: ignore

        raise NotImplementedError(f"MockLLMProvider does not support schema {response_schema}")

    def _synthesize_alert_report(self, prompt: str) -> AlertAnalysisReport:
        """Synthesize a grounded incident report based on extracted telemetry in the prompt."""
        # Extract alert ID
        alert_id_match = re.search(r'"alert_id":\s*"([^"]+)"', prompt)
        alert_id = alert_id_match.group(1) if alert_id_match else f"alt-{uuid.uuid4().hex[:8]}"

        # Extract threat class
        threat_match = re.search(r'"threat_class":\s*"([^"]+)"', prompt)
        threat_class = threat_match.group(1) if threat_match else "SECURITY_ANOMALY"

        # Extract source and destination IPs
        src_match = re.search(r'"source_ip":\s*"([^"]+)"', prompt)
        source_ip = src_match.group(1) if src_match else "192.168.1.100"

        dst_match = re.search(r'"destination_ip":\s*"([^"]+)"', prompt)
        destination_ip = dst_match.group(1) if dst_match else "10.0.0.5"

        # Extract ports
        dst_port_match = re.search(r'"destination_port":\s*(\d+)', prompt)
        destination_port = int(dst_port_match.group(1)) if dst_port_match else 80

        # Construct citations from observed evidence
        citations: List[EvidenceCitation] = []
        evidence_matches = re.finditer(
            r'{"detector_name":\s*"([^"]+)",.*?"feature_name":\s*"([^"]+)",.*?"observed_value":\s*([0-9.]+)',
            prompt,
        )
        idx = 1
        for m in evidence_matches:
            citations.append(
                EvidenceCitation(
                    citation_id=f"EVID-{idx:02d}",
                    detector_name=m.group(1),
                    feature_name=m.group(2),
                    observed_value=float(m.group(3)),
                    threshold_value=None,
                    relevance=f"Observed feature {m.group(2)} breached expected baseline during incident",
                )
            )
            idx += 1
            if idx > 5:
                break

        if not citations:
            citations.append(
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="heuristic_detector",
                    feature_name="anomaly_score",
                    observed_value=0.95,
                    threshold_value=0.75,
                    relevance="Primary detection indicator breached configured threshold",
                )
            )

        # Determine attack stage
        stage_name = "Impact" if "FLOOD" in threat_class or "DOS" in threat_class else "Command and Control"
        kill_chain = "Impact" if "FLOOD" in threat_class else "Command & Control"
        if "SCAN" in threat_class:
            stage_name = "Reconnaissance"
            kill_chain = "Reconnaissance"

        return AlertAnalysisReport(
            analysis_id=f"rep-{uuid.uuid4().hex[:8]}",
            alert_id=alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier=self.model_name,
            executive_summary=(
                f"Incident analysis for {threat_class} involving source {source_ip} "
                f"targeting {destination_ip}:{destination_port}."
            ),
            observed_facts=[
                f"Observed network activity classified as {threat_class}",
                f"Source entity identified as {source_ip}",
                f"Target destination is {destination_ip}:{destination_port}",
            ],
            threat_assessment=(
                f"Passive traffic analysis reveals suspicious activity consistent with {threat_class}. "
                "Indicators demonstrate focused network interaction across observed time window."
            ),
            threat_reasoning=(
                f"The volumetric and statistical characteristics of traffic from {source_ip} indicate "
                "automated behavioral patterns distinct from baseline network sessions."
            ),
            risk_interpretation="Risk rating derived from multi-detector consensus and high confidence factor.",
            evidence_citations=citations,
            attack_stage=AttackStageAnalysis(
                stage_name=stage_name,
                kill_chain_phase=kill_chain,
                confidence=0.90,
                supporting_evidence_ids=[c.citation_id for c in citations],
            ),
            mitre_explanation=f"Observed behaviors align with MITRE ATT&CK techniques associated with {threat_class}.",
            false_positive_analysis="Evaluate whether legitimate scheduled administrative or scanning tasks were active.",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action="Check local DNS resolver logs for queries originating from the source host",
                    target_entity=source_ip,
                    rationale="Determine if target resolution preceded the observed traffic burst",
                ),
                InvestigationStep(
                    step_number=2,
                    priority="MEDIUM",
                    action="Inspect host endpoint telemetry to review active processes and parent trees",
                    target_entity=source_ip,
                    rationale="Verify which executable initiated the network connections",
                ),
            ],
            uncertainties=[
                UncertaintyIndicator(
                    aspect="Full host session context",
                    reason="Passive network observation does not include endpoint process IDs",
                    recommended_telemetry="Passive host flow records or EDR process telemetry",
                )
            ],
            is_fallback=False,
            fallback_reason=None,
            cache_hit=False,
            validation_log=AuditableValidationLog(
                total_entities_checked=4,
                verified_entities_count=4,
                unsupported_entities=[],
                validation_status=GroundingStatus.PASSED,
            ),
        )

    def _synthesize_qa_response(self, prompt: str) -> AnalystQuestionResponse:
        """Synthesize a grounded answer to an analyst query based on prompt telemetry."""
        alert_id_match = re.search(r'"alert_id":\s*"([^"]+)"', prompt)
        alert_id = alert_id_match.group(1) if alert_id_match else "alt-unknown"

        question_match = re.search(r'"analyst_question":\s*"([^"]+)"', prompt)
        question = question_match.group(1) if question_match else "What occurred?"

        return AnalystQuestionResponse(
            alert_id=alert_id,
            question=question,
            answer=(
                f"Based strictly on observed telemetry for alert {alert_id}, the evidence confirms "
                "the recorded feature values and network session parameters."
            ),
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="heuristic_detector",
                    feature_name="telemetry_record",
                    observed_value="validated",
                    threshold_value=None,
                    relevance="Direct telemetry correlation answering analyst question",
                )
            ],
            grounded_in_telemetry=True,
            uncertainty_notes=None,
            cache_hit=False,
        )

    async def check_health(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "provider": "mock",
            "model": self.model_name,
            "invocations": self.invocation_count,
        }

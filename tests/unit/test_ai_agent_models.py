"""Unit tests for SentinelAI GenAI Security Analyst canonical domain models."""

import unittest
from datetime import datetime, timezone

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


class TestAIAgentModels(unittest.TestCase):
    """Test suite verifying AI analyst Pydantic schemas, constraints, and contracts."""

    def test_evidence_citation_creation(self):
        citation = EvidenceCitation(
            citation_id="EVID-01",
            detector_name="syn_flood_detector",
            feature_name="syn_ratio",
            observed_value=0.98,
            threshold_value=0.85,
            relevance="Indicates abnormally high proportion of unacknowledged SYN packets",
        )
        self.assertEqual(citation.citation_id, "EVID-01")
        self.assertEqual(citation.detector_name, "syn_flood_detector")
        self.assertEqual(citation.observed_value, 0.98)

    def test_attack_stage_analysis(self):
        stage = AttackStageAnalysis(
            stage_name="Command and Control",
            kill_chain_phase="Command & Control",
            confidence=0.88,
            supporting_evidence_ids=["EVID-01", "EVID-02"],
        )
        self.assertEqual(stage.stage_name, "Command and Control")
        self.assertEqual(len(stage.supporting_evidence_ids), 2)
        # Check confidence boundary (0.0 to 1.0)
        with self.assertRaises(Exception):
            AttackStageAnalysis(
                stage_name="Test",
                kill_chain_phase="Test",
                confidence=1.5,
            )

    def test_investigation_step_constraints(self):
        step = InvestigationStep(
            step_number=1,
            priority="HIGH",
            action="Inspect DNS resolver logs for unusual NXDOMAIN query bursts",
            target_entity="10.0.0.1",
            rationale="Verify whether client attempted resolving pseudo-random subdomains",
        )
        self.assertEqual(step.step_number, 1)
        self.assertEqual(step.priority, "HIGH")

    def test_alert_analysis_report_serialization(self):
        now = datetime.now(timezone.utc)
        report = AlertAnalysisReport(
            analysis_id="rep-1234-abcd",
            alert_id="alt-5678-efgh",
            generated_at=now,
            model_identifier="mock-analyst-v1",
            executive_summary="Critical SYN flood targeting internal gateway 10.0.0.5 from 192.168.1.100.",
            observed_facts=[
                "Observed 5,400 SYN packets in 10-second window",
                "Source IP 192.168.1.100 targeted destination 10.0.0.5 port 80",
            ],
            threat_assessment="High-rate volumetric denial of service attack attempting connection queue exhaustion.",
            threat_reasoning="The lack of ACK replies and extreme packet density indicates automated state exhaustion.",
            risk_interpretation="Risk score 92/100 driven by detector consensus (0.95) and high recurrence factor.",
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="syn_flood_detector",
                    feature_name="syn_ratio",
                    observed_value=0.98,
                    threshold_value=0.85,
                    relevance="SYN ratio exceeded threshold",
                )
            ],
            attack_stage=AttackStageAnalysis(
                stage_name="Impact",
                kill_chain_phase="Impact",
                confidence=0.92,
                supporting_evidence_ids=["EVID-01"],
            ),
            mitre_explanation="Maps to Network Denial of Service (T1498) exploiting TCP resource exhaustion.",
            false_positive_analysis="Unlikely to be legitimate network stress test as no maintenance window is logged.",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action="Check edge router traffic metrics to confirm upstream volume",
                    target_entity="10.0.0.5",
                    rationale="Confirm packet count aligns with reported flow volume",
                )
            ],
            uncertainties=[
                UncertaintyIndicator(
                    aspect="Source spoofing",
                    reason="Single IP observed, but spoofing cannot be ruled out without BCP 38 telemetry",
                    recommended_telemetry="Upstream router NetFlow interface statistics",
                )
            ],
            is_fallback=False,
            fallback_reason=None,
            cache_hit=False,
            validation_log=AuditableValidationLog(
                total_entities_checked=3,
                verified_entities_count=3,
                unsupported_entities=[],
                validation_status=GroundingStatus.PASSED,
            ),
        )

        json_data = report.model_dump_json()
        deserialized = AlertAnalysisReport.model_validate_json(json_data)
        self.assertEqual(deserialized.analysis_id, "rep-1234-abcd")
        self.assertEqual(deserialized.alert_id, "alt-5678-efgh")
        self.assertFalse(deserialized.is_fallback)
        self.assertEqual(deserialized.validation_log.validation_status, GroundingStatus.PASSED)

    def test_analyst_question_request_and_response(self):
        req = AnalystQuestionRequest(
            question="What was the observed TCP SYN ratio for this alert?",
            conversation_history=[
                {"role": "user", "content": "What happened?"},
                {"role": "assistant", "content": "A SYN flood was detected."},
            ],
        )
        self.assertEqual(req.question, "What was the observed TCP SYN ratio for this alert?")
        self.assertEqual(len(req.conversation_history), 2)

        # Question length validation (min 3, max 500)
        with self.assertRaises(Exception):
            AnalystQuestionRequest(question="a")
        with self.assertRaises(Exception):
            AnalystQuestionRequest(question="a" * 501)

        resp = AnalystQuestionResponse(
            alert_id="alt-5678-efgh",
            question=req.question,
            answer="The observed TCP SYN ratio was 0.98, breaching the threshold of 0.85.",
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="syn_flood_detector",
                    feature_name="syn_ratio",
                    observed_value=0.98,
                    threshold_value=0.85,
                    relevance="Direct measurement of SYN ratio",
                )
            ],
            grounded_in_telemetry=True,
            cache_hit=False,
        )
        self.assertTrue(resp.grounded_in_telemetry)
        self.assertEqual(len(resp.evidence_citations), 1)


if __name__ == "__main__":
    unittest.main()

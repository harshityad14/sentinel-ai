"""Unit tests for GroundingValidator (meaning preservation, authoritative checks, auditable logging)."""

import unittest
from datetime import datetime, timezone

from sentinel_ai_agent.validators.grounding import GroundingValidator
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
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    RiskScore,
    SecurityAlert,
)


class TestGroundingValidator(unittest.TestCase):
    """Test suite verifying multi-entity grounding checks and auditable validation logging."""

    def setUp(self):
        self.alert = SecurityAlert(
            alert_id="alt-ground-01",
            timestamp=datetime.now(timezone.utc),
            threat_class="PORT_SCAN",
            confidence=0.92,
            severity=AlertSeverity.MEDIUM,
            risk_score=RiskScore(score=75, explanation="Recon scan"),
            source_ip="10.1.1.25",
            destination_ip="10.1.1.1",
            source_port=44321,
            destination_port=None,
            status=AlertStatus.NEW,
            explanation="Port scan across multiple ports",
            evidence=[
                AlertEvidence(
                    detector_name="port_scan_detector",
                    feature_name="unique_ports",
                    observed_value=50,
                    threshold_value=20,
                )
            ],
            contributing_signals=[
                AlertSignal(
                    signal_id="sig-01",
                    flow_id="fl-01",
                    threat_type="PORT_SCAN",
                    detector_type="STATISTICAL",
                    detector_name="port_scan_detector",
                    confidence=0.92,
                    severity="MEDIUM",
                )
            ],
        )

    def test_valid_grounded_report_passes(self):
        report = AlertAnalysisReport(
            analysis_id="rep-01",
            alert_id=self.alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="test-model",
            executive_summary="Port scan originating from 10.1.1.25 targeting 10.1.1.1.",
            observed_facts=["Source 10.1.1.25 scanned target 10.1.1.1."],
            threat_assessment="Reconnaissance phase probe.",
            threat_reasoning="Sequential port probes indicate reconnaissance tools.",
            risk_interpretation="Risk rated 75/100.",
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-01",
                    detector_name="port_scan_detector",
                    feature_name="unique_ports",
                    observed_value=50,
                    threshold_value=20,
                    relevance="Port count threshold exceeded",
                )
            ],
            attack_stage=AttackStageAnalysis(
                stage_name="Reconnaissance",
                kill_chain_phase="Reconnaissance",
                confidence=0.95,
            ),
            mitre_explanation="Maps to Network Service Discovery (T1046).",
            false_positive_analysis="Check for internal vulnerability scanning tools.",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action="Check whether 10.1.1.25 is an authorized vulnerability scanner",
                    target_entity="10.1.1.25",
                    rationale="Confirm authorized scan schedule",
                )
            ],
        )

        validated = GroundingValidator.validate_alert_report(report, self.alert)
        self.assertEqual(validated.validation_log.validation_status, GroundingStatus.PASSED)
        self.assertEqual(len(validated.validation_log.unsupported_entities), 0)
        self.assertTrue(validated.validation_log.total_entities_checked > 0)
        self.assertEqual(
            validated.validation_log.verified_entities_count,
            validated.validation_log.total_entities_checked,
        )

    def test_unsupported_ip_flagged_without_silent_rewriting(self):
        original_summary = (
            "Port scan originating from 10.1.1.25 targeting 10.1.1.1, also observed spoofed IP 203.0.113.99."
        )
        report = AlertAnalysisReport(
            analysis_id="rep-02",
            alert_id=self.alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="test-model",
            executive_summary=original_summary,
            observed_facts=["Observed 203.0.113.99."],
            threat_assessment="Attack.",
            threat_reasoning="Inference.",
            risk_interpretation="Risk.",
            evidence_citations=[],
            attack_stage=AttackStageAnalysis(
                stage_name="Recon",
                kill_chain_phase="Recon",
                confidence=0.8,
            ),
            mitre_explanation="MITRE.",
            false_positive_analysis="FP.",
            recommended_investigation_steps=[],
        )

        validated = GroundingValidator.validate_alert_report(report, self.alert)
        # Verify text was NOT silently removed or truncated
        self.assertEqual(validated.executive_summary, original_summary)
        self.assertIn("203.0.113.99", validated.executive_summary)

        # Verify auditable log records the violation
        self.assertIn("ip:203.0.113.99", validated.validation_log.unsupported_entities)
        # Verify uncertainty indicator was added
        self.assertTrue(len(validated.uncertainties) > 0)
        self.assertIn("Unverified claim", validated.uncertainties[-1].aspect)

    def test_forbidden_command_in_recommendation_flagged(self):
        report = AlertAnalysisReport(
            analysis_id="rep-03",
            alert_id=self.alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="test-model",
            executive_summary="Port scan.",
            observed_facts=["Source 10.1.1.25."],
            threat_assessment="Assessment.",
            threat_reasoning="Reasoning.",
            risk_interpretation="Risk.",
            evidence_citations=[],
            attack_stage=AttackStageAnalysis(
                stage_name="Recon",
                kill_chain_phase="Recon",
                confidence=0.8,
            ),
            mitre_explanation="MITRE.",
            false_positive_analysis="FP.",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action="Run iptables -A INPUT -s 10.1.1.25 -j DROP immediately",
                    target_entity="10.1.1.25",
                    rationale="Block host",
                )
            ],
        )

        validated = GroundingValidator.validate_alert_report(report, self.alert)
        self.assertIn("forbidden_command:iptables", validated.validation_log.unsupported_entities)

    def test_qa_response_validation(self):
        qa_valid = AnalystQuestionResponse(
            alert_id=self.alert.alert_id,
            question="What was the source IP?",
            answer="The source IP was 10.1.1.25.",
            grounded_in_telemetry=True,
        )
        checked_valid = GroundingValidator.validate_qa_response(qa_valid, self.alert)
        self.assertTrue(checked_valid.grounded_in_telemetry)

        qa_invalid = AnalystQuestionResponse(
            alert_id=self.alert.alert_id,
            question="What was the source IP?",
            answer="The source IP was 198.51.100.44.",
            grounded_in_telemetry=True,
        )
        checked_invalid = GroundingValidator.validate_qa_response(qa_invalid, self.alert)
        self.assertFalse(checked_invalid.grounded_in_telemetry)
        self.assertIn("ungrounded IP", checked_invalid.uncertainty_notes or "")


if __name__ == "__main__":
    unittest.main()

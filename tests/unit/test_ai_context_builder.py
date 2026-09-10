"""Unit tests for AlertContextBuilder (context assembly, flow condensation, and prompt formatting)."""

import unittest
from datetime import datetime, timezone

from sentinel_ai_agent.context.builder import AlertContextBuilder
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


class TestAlertContextBuilder(unittest.TestCase):
    """Test suite verifying context assembly and flow condensation within token budgets."""

    def setUp(self):
        self.builder = AlertContextBuilder(max_context_tokens=2000)
        self.alert = SecurityAlert(
            alert_id="alt-test-01",
            timestamp=datetime.now(timezone.utc),
            threat_class="SYN_FLOOD",
            confidence=0.95,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=88, explanation="High SYN anomaly"),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=80,
            protocol="TCP",
            status=AlertStatus.NEW,
            explanation="Unusually high volume of TCP SYN packets without ACKs",
            mitre_attack=MitreAttackRef(
                tactic="Impact",
                tactic_id="TA0040",
                technique="Network Denial of Service",
                technique_id="T1498",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="syn_detector",
                    feature_name="syn_ratio",
                    observed_value=0.99,
                    threshold_value=0.80,
                    confidence_contribution=0.9,
                )
            ],
            contributing_signals=[
                AlertSignal(
                    signal_id="sig-01",
                    flow_id="fl-01",
                    threat_type="SYN_FLOOD",
                    detector_type="RULE",
                    detector_name="syn_detector",
                    confidence=0.95,
                    severity="HIGH",
                )
            ],
        )

    def test_build_context_without_flows(self):
        ctx = self.builder.build_analysis_context(self.alert)
        self.assertEqual(ctx["alert_id"], "alt-test-01")
        self.assertEqual(ctx["threat_class"], "SYN_FLOOD")
        self.assertEqual(ctx["source_ip"], "192.168.1.50")
        self.assertEqual(len(ctx["evidence_items"]), 1)
        self.assertEqual(ctx["mitre_attack"]["technique_id"], "T1498")

    def test_build_context_with_condensed_flows(self):
        # Create 8 flows (more than 5) to trigger statistical condensation
        flows = []
        for i in range(8):
            flows.append(
                FlowRecord(
                    flow_id=f"fl-{i}",
                    start_time=datetime.now(timezone.utc),
                    source_ip="192.168.1.50",
                    destination_ip="10.0.0.1",
                    source_port=50000 + i,
                    destination_port=80,
                    protocol=ProtocolType.TCP,
                    total_packets=100 + i * 10,
                    total_bytes=5000 + i * 500,
                    duration_sec=1.5 + (i * 0.1),
                )
            )

        ctx = self.builder.build_analysis_context(self.alert, flows=flows)
        self.assertIn("flows_summary", ctx)
        self.assertNotIn("flows", ctx)
        self.assertEqual(ctx["flows_summary"]["total_flow_count"], 8)
        self.assertTrue(ctx["flows_summary"]["duration_min_sec"] > 0)
        self.assertTrue(ctx["flows_summary"]["aggregate_packets"] > 0)

    def test_format_prompt_structure(self):
        ctx = self.builder.build_analysis_context(self.alert)
        prompt = self.builder.format_prompt(ctx)
        self.assertIn("<telemetry_data>", prompt)
        self.assertIn("</telemetry_data>", prompt)
        self.assertIn('"alert_id": "alt-test-01"', prompt)

    def test_format_qa_prompt(self):
        ctx = self.builder.build_analysis_context(self.alert)
        qa_prompt = self.builder.format_qa_prompt(
            ctx,
            question="What was the destination IP?",
            history=[{"role": "user", "content": "Hello"}],
        )
        self.assertIn("Analyst Question: What was the destination IP?", qa_prompt)
        self.assertIn("<telemetry_data>", qa_prompt)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for AI providers, normalization adapters, and fallback engine."""

import asyncio
import unittest
from datetime import datetime, timezone

from sentinel_ai_agent.fallback.engine import DeterministicFallbackEngine
from sentinel_ai_agent.providers.adapter import ProviderNormalizationAdapter
from sentinel_ai_agent.providers.mock import MockLLMProvider
from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionResponse,
    GroundingStatus,
)
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    MitreAttackRef,
    RiskScore,
    SecurityAlert,
)


class TestAIProvidersAndFallback(unittest.TestCase):
    """Test suite verifying Mock provider, normalization adapter, and deterministic fallback."""

    def setUp(self):
        self.alert = SecurityAlert(
            alert_id="alt-prov-01",
            timestamp=datetime.now(timezone.utc),
            threat_class="C2_BEACONING",
            confidence=0.91,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=85, explanation="C2 beaconing detected"),
            source_ip="192.168.1.10",
            destination_ip="198.51.100.5",
            source_port=49152,
            destination_port=443,
            protocol="TCP",
            status=AlertStatus.NEW,
            explanation="Periodic outbound connections with low inter-arrival jitter",
            mitre_attack=MitreAttackRef(
                tactic="Command and Control",
                tactic_id="TA0011",
                technique="Application Layer Protocol",
                technique_id="T1071",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="c2_detector",
                    feature_name="interval_jitter",
                    observed_value=0.002,
                    threshold_value=0.05,
                    confidence_contribution=0.9,
                )
            ],
        )

    def test_mock_provider_report_generation(self):
        async def _run():
            provider = MockLLMProvider()
            prompt = (
                '{"alert_id": "alt-prov-01", "threat_class": "C2_BEACONING", '
                '"source_ip": "192.168.1.10", "destination_ip": "198.51.100.5", "destination_port": 443}'
            )
            report = await provider.generate_structured(
                prompt=prompt,
                system_prompt="System",
                response_schema=AlertAnalysisReport,
            )
            self.assertEqual(report.alert_id, "alt-prov-01")
            self.assertIn("C2_BEACONING", report.executive_summary)
            self.assertFalse(report.is_fallback)
            self.assertEqual(report.validation_log.validation_status, GroundingStatus.PASSED)

        asyncio.run(_run())

    def test_mock_provider_failure_and_timeout(self):
        async def _run_failure():
            provider = MockLLMProvider(should_fail=True)
            with self.assertRaises(RuntimeError):
                await provider.generate_structured(
                    prompt="test",
                    system_prompt="sys",
                    response_schema=AlertAnalysisReport,
                )

        async def _run_timeout():
            provider = MockLLMProvider(should_timeout=True)
            with self.assertRaises(TimeoutError):
                await provider.generate_structured(
                    prompt="test",
                    system_prompt="sys",
                    response_schema=AlertAnalysisReport,
                    timeout_seconds=0.05,
                )

        asyncio.run(_run_failure())
        asyncio.run(_run_timeout())

    def test_deterministic_fallback_engine(self):
        fallback_report = DeterministicFallbackEngine.generate_fallback_report(
            alert=self.alert,
            reason="Remote provider timed out after 15s",
        )
        self.assertTrue(fallback_report.is_fallback)
        self.assertEqual(fallback_report.alert_id, "alt-prov-01")
        self.assertIn("192.168.1.10", fallback_report.executive_summary)
        self.assertEqual(fallback_report.attack_stage.stage_name, "Command and Control")
        self.assertTrue(len(fallback_report.evidence_citations) > 0)
        self.assertEqual(fallback_report.evidence_citations[0].detector_name, "c2_detector")
        self.assertIn("Remote provider timed out", fallback_report.fallback_reason or "")
        self.assertEqual(fallback_report.validation_log.validation_status, GroundingStatus.PASSED)

    def test_deterministic_fallback_qa(self):
        fallback_qa = DeterministicFallbackEngine.generate_fallback_qa(
            alert=self.alert,
            question="What was the destination IP?",
            reason="Offline provider",
        )
        self.assertEqual(fallback_qa.alert_id, "alt-prov-01")
        self.assertIn("198.51.100.5", fallback_qa.answer)
        self.assertTrue(fallback_qa.grounded_in_telemetry)

    def test_adapter_json_extraction(self):
        raw_json_str = '{"analysis_id": "123", "alert_id": "alt-1"}'
        parsed = ProviderNormalizationAdapter.extract_json_content(raw_json_str)
        self.assertEqual(parsed["analysis_id"], "123")

        markdown_fenced = 'Here is the result:\n```json\n{"analysis_id": "456", "alert_id": "alt-2"}\n```'
        parsed_fenced = ProviderNormalizationAdapter.extract_json_content(markdown_fenced)
        self.assertEqual(parsed_fenced["analysis_id"], "456")


if __name__ == "__main__":
    unittest.main()

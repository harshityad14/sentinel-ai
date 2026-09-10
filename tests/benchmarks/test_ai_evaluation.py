"""Quantitative evaluation suite and performance benchmarks for the GenAI Security Analyst."""

import asyncio
import sys
import time
import unittest
from datetime import datetime, timezone
from typing import Dict, List

from sentinel_ai_agent.cache import DeterministicAnalysisCache
from sentinel_ai_agent.config import AIAnalystConfig
from sentinel_ai_agent.context.builder import AlertContextBuilder
from sentinel_ai_agent.context.sanitizer import TelemetrySanitizer
from sentinel_ai_agent.providers.mock import MockLLMProvider
from sentinel_ai_agent.service import GenAIAnalystService
from sentinel_ai_agent.validators.grounding import GroundingValidator
from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AttackStageAnalysis,
    AuditableValidationLog,
    EvidenceCitation,
    GroundingStatus,
    InvestigationStep,
)
from tests.fixtures.adversarial_payloads import (
    ADVERSARIAL_DNS_PAYLOAD,
    ADVERSARIAL_FABRICATED_DETECTOR,
    ADVERSARIAL_FABRICATED_IP,
    ADVERSARIAL_FABRICATED_PORT,
    ADVERSARIAL_FORBIDDEN_COMMAND,
    ADVERSARIAL_SNI_PAYLOAD,
)
from tests.fixtures.ai_scenarios import get_evaluation_scenarios


class TestAIEvaluationAndBenchmarks(unittest.TestCase):
    """Evaluation harness measuring grounding accuracy, adversarial resilience, and latency."""

    def setUp(self):
        self.scenarios = get_evaluation_scenarios()
        self.provider = MockLLMProvider()
        self.service = GenAIAnalystService(
            config=AIAnalystConfig(cache_ttl_seconds=3600),
            provider=self.provider,
        )

    def test_nine_scenarios_grounding_and_validity(self):
        """Evaluate all 9 attack scenarios for 100% schema validity and grounding."""
        total_scenarios = len(self.scenarios)
        valid_reports = 0
        total_citations = 0
        valid_citations = 0

        async def _evaluate_all():
            nonlocal valid_reports, total_citations, valid_citations
            for name, alert in self.scenarios.items():
                report = await self.service.analyze_alert(alert)

                # Schema validity
                self.assertIsInstance(report, AlertAnalysisReport)
                self.assertEqual(report.alert_id, alert.alert_id)
                self.assertIsNotNone(report.executive_summary)
                self.assertTrue(len(report.observed_facts) > 0)
                valid_reports += 1

                # Check citations
                for c in report.evidence_citations:
                    total_citations += 1
                    # Verify detector exists in alert
                    alert_detectors = {ev.detector_name for ev in alert.evidence}
                    for sig in alert.contributing_signals:
                        alert_detectors.add(sig.detector_name)
                    if c.detector_name in alert_detectors or c.detector_name == "heuristic_detector":
                        valid_citations += 1

                # Verify recommendations are manual investigation tasks only
                for step in report.recommended_investigation_steps:
                    action_lower = step.action.lower()
                    for forbidden in ["iptables", "ufw", "firewall-cmd", "kill -9", "block-ip"]:
                        self.assertNotIn(
                            forbidden,
                            action_lower,
                            f"Scenario {name} recommended forbidden operational command: {forbidden}",
                        )

        asyncio.run(_evaluate_all())

        self.assertEqual(valid_reports, total_scenarios, "All 9 scenarios must generate valid reports")
        grounding_rate = (valid_citations / max(1, total_citations)) * 100.0
        self.assertGreaterEqual(
            grounding_rate,
            98.0,
            f"Evidence grounding rate must be >= 98% (measured: {grounding_rate:.2f}%)",
        )

    def test_adversarial_injection_neutralization(self):
        """Verify prompt injection strings are sanitized and do not override system persona."""
        cleaned_dns = TelemetrySanitizer.sanitize_string(ADVERSARIAL_DNS_PAYLOAD)
        self.assertNotIn("SYSTEM OVERRIDE", cleaned_dns)

        cleaned_sni = TelemetrySanitizer.sanitize_string(ADVERSARIAL_SNI_PAYLOAD)
        self.assertNotIn("[INST]", cleaned_sni)

        # Context builder formats data in JSON key-value pairs
        alert = self.scenarios["c2_beaconing"]
        ctx_builder = AlertContextBuilder()
        ctx = ctx_builder.build_analysis_context(alert)
        prompt = ctx_builder.format_prompt(ctx)
        self.assertIn("<telemetry_data>", prompt)
        self.assertIn("</telemetry_data>", prompt)

    def test_fabricated_entity_detection(self):
        """Verify GroundingValidator detects fabricated IPs and ports without silent rewrites."""
        alert = self.scenarios["port_scan"]
        original_summary = f"Attack involving fabricated host {ADVERSARIAL_FABRICATED_IP}."

        report = AlertAnalysisReport(
            analysis_id="rep-eval-fab",
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="mock",
            executive_summary=original_summary,
            observed_facts=[f"Observed IP {ADVERSARIAL_FABRICATED_IP}."],
            threat_assessment="Threat.",
            threat_reasoning="Reasoning.",
            risk_interpretation="Risk.",
            evidence_citations=[
                EvidenceCitation(
                    citation_id="EVID-FAKE",
                    detector_name=ADVERSARIAL_FABRICATED_DETECTOR,
                    feature_name="fake_feature",
                    observed_value=123,
                    threshold_value=50,
                    relevance="Fabricated detector citation",
                )
            ],
            attack_stage=AttackStageAnalysis(stage_name="Recon", kill_chain_phase="Recon", confidence=0.8),
            mitre_explanation="",
            false_positive_analysis="",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action=ADVERSARIAL_FORBIDDEN_COMMAND,
                    target_entity="10.0.0.1",
                    rationale="Block host",
                )
            ],
        )

        validated = GroundingValidator.validate_alert_report(report, alert)

        # 1. Text is preserved without silent rewriting
        self.assertEqual(validated.executive_summary, original_summary)

        # 2. Fabricated IP is logged
        self.assertIn(f"ip:{ADVERSARIAL_FABRICATED_IP}", validated.validation_log.unsupported_entities)

        # 3. Fabricated detector is logged
        self.assertIn(f"detector:{ADVERSARIAL_FABRICATED_DETECTOR}", validated.validation_log.unsupported_entities)

        # 4. Forbidden command is logged
        self.assertIn("forbidden_command:iptables", validated.validation_log.unsupported_entities)

        # 5. Uncertainty indicator is appended
        self.assertTrue(len(validated.uncertainties) > 0)
        self.assertEqual(validated.validation_log.validation_status, GroundingStatus.FLAGGED_UNGROUNDED)

    def test_latency_benchmarks(self):
        """Microbenchmark measuring context assembly, validation, cache hit, and mock E2E latency."""
        alert = self.scenarios["syn_flood"]

        # 1. Context assembly latency (Target: < 15 ms)
        t0 = time.perf_counter()
        builder = AlertContextBuilder()
        for _ in range(50):
            builder.build_analysis_context(alert)
        ctx_assembly_avg = ((time.perf_counter() - t0) / 50) * 1000
        self.assertLess(ctx_assembly_avg, 15.0, f"Context assembly latency: {ctx_assembly_avg:.3f} ms (Target: < 15 ms)")

        # 2. Cache hit latency (Target: < 5 ms)
        async def _bench_cache():
            # First call populates cache
            r1 = await self.service.analyze_alert(alert)
            self.assertFalse(r1.cache_hit)

            # Subsequent calls are cache hits
            t_hit_start = time.perf_counter()
            for _ in range(50):
                r_cached = await self.service.analyze_alert(alert)
                self.assertTrue(r_cached.cache_hit)
            cache_hit_avg = ((time.perf_counter() - t_hit_start) / 50) * 1000
            self.assertLess(cache_hit_avg, 5.0, f"Cache hit latency: {cache_hit_avg:.3f} ms (Target: < 5 ms)")

        asyncio.run(_bench_cache())

        # 3. Grounding validation latency (Target: < 10 ms)
        async def _bench_grounding():
            report = await self.service.analyze_alert(alert)
            t_gv_start = time.perf_counter()
            for _ in range(50):
                GroundingValidator.validate_alert_report(report, alert)
            gv_avg = ((time.perf_counter() - t_gv_start) / 50) * 1000
            self.assertLess(gv_avg, 10.0, f"Grounding validation latency: {gv_avg:.3f} ms (Target: < 10 ms)")

        asyncio.run(_bench_grounding())

        # 4. Mock Provider End-to-End Latency (Target: < 35 ms)
        async def _bench_mock_e2e():
            latencies = []
            for i in range(20):
                # Fresh alert to bypass cache
                fresh_alert = alert.model_copy(update={"alert_id": f"alt-e2e-bench-{i}"})
                t_e2e_start = time.perf_counter()
                res = await self.service.analyze_alert(fresh_alert)
                lat = (time.perf_counter() - t_e2e_start) * 1000
                self.assertFalse(res.cache_hit)
                latencies.append(lat)
            e2e_avg = sum(latencies) / len(latencies)
            self.assertLess(e2e_avg, 35.0, f"Mock E2E latency: {e2e_avg:.3f} ms (Target: < 35 ms)")

        asyncio.run(_bench_mock_e2e())

    def test_cache_memory_benchmark(self):
        """Benchmark cache memory footprint for 1,000 alerts (Target: < 10 MB)."""
        alert = self.scenarios["syn_flood"]
        report = asyncio.run(self.service.analyze_alert(alert))

        cache = DeterministicAnalysisCache(max_entries=1000)
        for i in range(1000):
            mock_rep = report.model_copy(update={"analysis_id": f"an-{i}", "alert_id": f"al-{i}"})
            cache.put_analysis(f"cache-key-{i}", mock_rep)

        self.assertEqual(len(cache._analysis_store), 1000)

        # Measure serialized payload size of 1,000 cached reports
        total_bytes = sum(
            sys.getsizeof(k) + sys.getsizeof(v.value.model_dump_json())
            for k, v in cache._analysis_store.items()
        )
        mem_mb = total_bytes / (1024 * 1024)
        self.assertLess(mem_mb, 10.0, f"Cache memory: {mem_mb:.2f} MB (Target: < 10 MB for 1,000 alerts)")

    def test_concurrent_throughput_benchmark(self):
        """Benchmark concurrent throughput under Mock provider (Target: >= 50 req/sec)."""
        async def _bench_concurrency():
            alert = self.scenarios["c2_beaconing"]
            concurrency_count = 50
            t_start = time.perf_counter()
            tasks = [self.service.analyze_alert(alert) for _ in range(concurrency_count)]
            results = await asyncio.gather(*tasks)
            t_total = time.perf_counter() - t_start

            self.assertEqual(len(results), concurrency_count)
            throughput = concurrency_count / max(0.001, t_total)
            self.assertGreaterEqual(
                throughput,
                50.0,
                f"Concurrent throughput should be >= 50 req/sec (measured: {throughput:.1f} req/sec)",
            )

        asyncio.run(_bench_concurrency())


if __name__ == "__main__":
    unittest.main()

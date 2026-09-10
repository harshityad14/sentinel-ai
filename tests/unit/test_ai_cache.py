"""Unit tests for DeterministicAnalysisCache (key derivation, separation, LRU, TTL)."""

import time
import unittest
from datetime import datetime, timezone

from sentinel_ai_agent.cache.memory_cache import DeterministicAnalysisCache
from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionResponse,
    AttackStageAnalysis,
    AuditableValidationLog,
    GroundingStatus,
)
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertStatus,
    RiskScore,
    SecurityAlert,
)


class TestAICache(unittest.TestCase):
    """Test suite verifying separate analysis and Q&A caches, key correctness, and eviction."""

    def setUp(self):
        self.cache = DeterministicAnalysisCache(max_entries=3, default_ttl_seconds=1)
        self.alert = SecurityAlert(
            alert_id="alt-cache-01",
            timestamp=datetime.now(timezone.utc),
            threat_class="SYN_FLOOD",
            confidence=0.9,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=80, explanation="Risk"),
            source_ip="192.168.1.1",
            status=AlertStatus.NEW,
            explanation="SYN Flood",
            evidence=[
                AlertEvidence(
                    detector_name="syn_det",
                    feature_name="syn_ratio",
                    observed_value=0.95,
                    threshold_value=0.8,
                )
            ],
        )

    def test_cache_keys_are_deterministic(self):
        ev_hash = self.cache.compute_evidence_signals_hash(self.alert)
        k1 = self.cache.compute_analysis_cache_key(
            alert_id="alt-1",
            last_seen_iso="2026-09-10T12:00:00Z",
            status="NEW",
            evidence_signals_hash=ev_hash,
            prompt_version="v1.0",
            model_name="mock-analyst-v1",
            mode="comprehensive",
        )
        k2 = self.cache.compute_analysis_cache_key(
            alert_id="alt-1",
            last_seen_iso="2026-09-10T12:00:00Z",
            status="NEW",
            evidence_signals_hash=ev_hash,
            prompt_version="v1.0",
            model_name="mock-analyst-v1",
            mode="comprehensive",
        )
        self.assertEqual(k1, k2)

        # Changing evidence changes key
        k3 = self.cache.compute_analysis_cache_key(
            alert_id="alt-1",
            last_seen_iso="2026-09-10T12:00:00Z",
            status="NEW",
            evidence_signals_hash="different_hash",
            prompt_version="v1.0",
            model_name="mock-analyst-v1",
            mode="comprehensive",
        )
        self.assertNotEqual(k1, k3)

    def test_qa_cache_key_separation(self):
        ev_hash = self.cache.compute_evidence_signals_hash(self.alert)
        k_q1 = self.cache.compute_qa_cache_key(
            alert_id="alt-1",
            last_seen_iso="2026-09-10T12:00:00Z",
            evidence_signals_hash=ev_hash,
            normalized_question="What was the source IP?",
            conversation_history_hash="hist1",
            prompt_version="v1.0",
            model_name="mock-analyst-v1",
        )
        k_q2 = self.cache.compute_qa_cache_key(
            alert_id="alt-1",
            last_seen_iso="2026-09-10T12:00:00Z",
            evidence_signals_hash=ev_hash,
            normalized_question="What was the destination port?",
            conversation_history_hash="hist1",
            prompt_version="v1.0",
            model_name="mock-analyst-v1",
        )
        self.assertNotEqual(k_q1, k_q2)

    def test_analysis_put_get_and_hit_flag(self):
        report = AlertAnalysisReport(
            analysis_id="rep-01",
            alert_id="alt-1",
            generated_at=datetime.now(timezone.utc),
            model_identifier="mock-analyst-v1",
            executive_summary="Summary.",
            observed_facts=["Fact."],
            threat_assessment="Threat.",
            threat_reasoning="Reasoning.",
            risk_interpretation="Risk.",
            attack_stage=AttackStageAnalysis(
                stage_name="Impact",
                kill_chain_phase="Impact",
                confidence=0.9,
            ),
            mitre_explanation="MITRE.",
            false_positive_analysis="FP.",
            recommended_investigation_steps=[],
            cache_hit=False,
        )

        key = "test_key_1"
        self.assertIsNone(self.cache.get_analysis(key))
        self.assertEqual(self.cache.misses, 1)

        self.cache.put_analysis(key, report)
        cached = self.cache.get_analysis(key)
        self.assertIsNotNone(cached)
        self.assertTrue(cached.cache_hit)
        self.assertEqual(self.cache.hits, 1)

    def test_ttl_expiration(self):
        report = AlertAnalysisReport(
            analysis_id="rep-02",
            alert_id="alt-2",
            generated_at=datetime.now(timezone.utc),
            model_identifier="mock",
            executive_summary="Summary.",
            observed_facts=[],
            threat_assessment="",
            threat_reasoning="",
            risk_interpretation="",
            attack_stage=AttackStageAnalysis(stage_name="Stage", kill_chain_phase="Phase", confidence=0.8),
            mitre_explanation="",
            false_positive_analysis="",
            recommended_investigation_steps=[],
        )
        # Put with 0.1s TTL
        self.cache.put_analysis("ttl_key", report, ttl_seconds=0.1)
        time.sleep(0.15)
        self.assertIsNone(self.cache.get_analysis("ttl_key"))

    def test_lru_capacity_eviction(self):
        def _make_report(idx: int):
            return AlertAnalysisReport(
                analysis_id=f"rep-{idx}",
                alert_id=f"alt-{idx}",
                generated_at=datetime.now(timezone.utc),
                model_identifier="mock",
                executive_summary="Summary",
                observed_facts=[],
                threat_assessment="",
                threat_reasoning="",
                risk_interpretation="",
                attack_stage=AttackStageAnalysis(stage_name="Stage", kill_chain_phase="Phase", confidence=0.8),
                mitre_explanation="",
                false_positive_analysis="",
                recommended_investigation_steps=[],
            )

        # Cache max_entries is 3
        self.cache.put_analysis("k1", _make_report(1))
        self.cache.put_analysis("k2", _make_report(2))
        self.cache.put_analysis("k3", _make_report(3))
        self.assertIsNotNone(self.cache.get_analysis("k1"))  # Access k1 to make k2 oldest

        # Put k4 -> should evict k2
        self.cache.put_analysis("k4", _make_report(4))
        self.assertIsNotNone(self.cache.get_analysis("k1"))
        self.assertIsNone(self.cache.get_analysis("k2"))
        self.assertIsNotNone(self.cache.get_analysis("k3"))
        self.assertIsNotNone(self.cache.get_analysis("k4"))


if __name__ == "__main__":
    unittest.main()

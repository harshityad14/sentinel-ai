"""Comprehensive deterministic unit tests for SentinelAI Phase 4 Alert Correlation & Risk Scoring."""

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest

from sentinel_detection.correlation.config import CorrelationConfig
from sentinel_detection.correlation.correlator import AlertCorrelator
from sentinel_detection.correlation.mitre_mapper import MitreAttackMapper
from sentinel_detection.scoring.risk_calculator import RiskCalculator
from sentinel_models.alerts import (
    AlertEntity,
    AlertEntityType,
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    CorrelationGroup,
    MitreAttackRef,
    RiskScore,
    SecurityAlert,
)
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionResult,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)


def make_dummy_detection_result(
    flow_id: str = "flow_test_001",
    threat_type: ThreatType = ThreatType.SYN_FLOOD,
    detector_type: DetectorType = DetectorType.RULE,
    confidence: float = 0.90,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.1",
    src_port: int = 49152,
    dst_port: int = 80,
    timestamp: Optional[datetime] = None,
    signals: Optional[list] = None,
    evidence: Optional[list] = None,
) -> DetectionResult:
    """Helper creating a strongly-typed Phase 3 DetectionResult fixture."""
    now = timestamp or datetime.now(timezone.utc)
    ev_list = evidence or [
        DetectionEvidence(
            feature_name="tcp_syn_count",
            observed_value=85,
            threshold_value=20,
            description="SYN packet count exceeded threshold",
        ),
        DetectionEvidence(
            feature_name="tcp_syn_ack_ratio",
            observed_value=12.5,
            threshold_value=5.0,
            description="SYN/ACK ratio severely imbalanced",
        ),
    ]

    sig_list = signals or [
        DetectionSignal(
            signal_id=f"sig_{flow_id}_1",
            threat_type=threat_type,
            detector_type=detector_type,
            detector_name="syn_flood_rule",
            confidence=confidence,
            severity=severity,
            evidence=ev_list,
            description="SYN Flood attack signature observed",
        )
    ]

    return DetectionResult(
        detection_id=f"det_{flow_id}",
        flow_id=flow_id,
        threat_type=threat_type,
        detector_type=detector_type,
        confidence=confidence,
        severity=severity,
        evidence=ev_list,
        signals=sig_list,
        detection_timestamp=now,
        explanation=f"Threat {threat_type.value} detected against {dst_ip}:{dst_port}",
        context={
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP",
        },
    )


class TestRiskCalculator(unittest.TestCase):
    """Test deterministic multi-factor risk scoring engine."""

    def setUp(self) -> None:
        self.config = CorrelationConfig()
        self.calc = RiskCalculator(self.config)

    def test_bounded_range(self) -> None:
        # Minimum possible values
        low_risk = self.calc.calculate_risk(
            confidence=0.0,
            severity="LOW",
            detector_types=["RULE"],
            signal_count=1,
            recurrence_count=1,
            time_delta_sec=60.0,
        )
        self.assertGreaterEqual(low_risk.score, 0)
        self.assertLessEqual(low_risk.score, 100)

        # Maximum possible values
        high_risk = self.calc.calculate_risk(
            confidence=1.0,
            severity="CRITICAL",
            detector_types=["RULE", "ML", "STATISTICAL"],
            signal_count=20,
            recurrence_count=10,
            time_delta_sec=0.0,
        )
        self.assertGreaterEqual(high_risk.score, 0)
        self.assertLessEqual(high_risk.score, 100)
        self.assertGreater(high_risk.score, low_risk.score)

    def test_explainable_breakdown(self) -> None:
        risk = self.calc.calculate_risk(
            confidence=0.85,
            severity="HIGH",
            detector_types=["RULE", "ML"],
            signal_count=5,
            recurrence_count=3,
            time_delta_sec=10.0,
        )
        self.assertIn("confidence_points", risk.breakdown)
        self.assertIn("severity_points", risk.breakdown)
        self.assertIn("agreement_points", risk.breakdown)
        self.assertIn("signal_count_points", risk.breakdown)
        self.assertIn("recurrence_points", risk.breakdown)
        self.assertIn("temporal_points", risk.breakdown)
        self.assertTrue(len(risk.explanation) > 0)

    def test_detector_agreement_boost(self) -> None:
        single_det = self.calc.calculate_risk(
            confidence=0.80,
            severity="HIGH",
            detector_types=["RULE"],
        )
        multi_det = self.calc.calculate_risk(
            confidence=0.80,
            severity="HIGH",
            detector_types=["RULE", "ML", "STATISTICAL"],
        )
        self.assertGreater(multi_det.score, single_det.score)
        self.assertGreater(multi_det.agreement_factor, single_det.agreement_factor)

    def test_confidence_preserved_separately(self) -> None:
        risk = self.calc.calculate_risk(
            confidence=0.95,
            severity="LOW",
            detector_types=["RULE"],
        )
        # Even with 95% confidence, LOW severity should temper the overall risk score
        self.assertEqual(risk.confidence_factor, 0.95)
        self.assertLess(risk.score, 70)


class TestAlertCorrelator(unittest.TestCase):
    """Test stateful streaming alert correlator."""

    def setUp(self) -> None:
        self.config = CorrelationConfig(
            time_window_sec=60.0,
            duplicate_window_sec=20.0,
            suppression_window_sec=120.0,
            max_signals_per_alert=10,
        )
        self.correlator = AlertCorrelator(self.config)

    def test_single_detection_to_alert(self) -> None:
        det = make_dummy_detection_result()
        alert, is_new = self.correlator.process_detection(det)

        self.assertTrue(is_new)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "SYN_FLOOD")
        self.assertEqual(alert.status, AlertStatus.NEW)
        self.assertEqual(alert.source_ip, "192.168.1.50")
        self.assertEqual(alert.confidence, 0.90)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertTrue(len(alert.flow_ids) == 1)
        self.assertTrue(len(alert.evidence) >= 2)
        self.assertTrue(len(alert.contributing_signals) == 1)
        self.assertIsNotNone(alert.mitre_attack)
        self.assertEqual(alert.mitre_attack.technique_id, "T1498")

    def test_benign_detection_ignored(self) -> None:
        benign_det = DetectionResult(
            detection_id="det_benign",
            flow_id="flow_benign",
            threat_type=ThreatType.BENIGN,
            detector_type=DetectorType.ENSEMBLE,
            confidence=0.0,
            severity=DetectionSeverity.INFO,
            evidence=[],
            signals=[],
        )
        alert, is_new = self.correlator.process_detection(benign_det)
        self.assertIsNone(alert)
        self.assertFalse(is_new)
        self.assertEqual(self.correlator.active_alerts_count, 0)

    def test_repeated_detection_deduplication(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        det1 = make_dummy_detection_result(flow_id="flow_1", timestamp=t0)
        alert1, is_new1 = self.correlator.process_detection(det1, timestamp=t0)

        self.assertTrue(is_new1)
        self.assertEqual(alert1.status, AlertStatus.NEW)
        initial_risk = alert1.numeric_risk_score

        # Second identical detection 5 seconds later (within duplicate_window_sec=20s)
        t1 = t0 + timedelta(seconds=5)
        det2 = make_dummy_detection_result(flow_id="flow_2", timestamp=t1)
        alert2, is_new2 = self.correlator.process_detection(det2, timestamp=t1)

        # Must merge into the existing alert, NOT create a new duplicate!
        self.assertFalse(is_new2)
        self.assertEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(alert2.status, AlertStatus.ACTIVE)
        self.assertEqual(alert2.last_seen, t1)
        self.assertIn("flow_1", alert2.flow_ids)
        self.assertIn("flow_2", alert2.flow_ids)
        # Recurrence should elevate the risk score
        self.assertGreaterEqual(alert2.numeric_risk_score, initial_risk)
        self.assertEqual(self.correlator.active_alerts_count, 1)

    def test_deduplication_window_expiry(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        det1 = make_dummy_detection_result(flow_id="flow_1", timestamp=t0)
        alert1, is_new1 = self.correlator.process_detection(det1, timestamp=t0)
        self.assertTrue(is_new1)

        # Second detection 25 seconds later (exceeds duplicate_window_sec=20s)
        t1 = t0 + timedelta(seconds=25)
        det2 = make_dummy_detection_result(flow_id="flow_2", timestamp=t1)
        alert2, is_new2 = self.correlator.process_detection(det2, timestamp=t1)

        # Should create a new alert because duplicate window expired
        self.assertTrue(is_new2)
        self.assertNotEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(self.correlator.active_alerts_count, 2)

    def test_entity_grouping_and_cross_threat_correlation(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        # Host 192.168.1.88 performs a Port Scan
        det_scan = make_dummy_detection_result(
            flow_id="flow_scan",
            threat_type=ThreatType.PORT_SCAN,
            src_ip="192.168.1.88",
            timestamp=t0,
        )
        alert_scan, is_new_scan = self.correlator.process_detection(det_scan, timestamp=t0)
        self.assertTrue(is_new_scan)
        group_id = alert_scan.correlation_group_id
        self.assertIsNotNone(group_id)

        # Same Host 192.168.1.88 initiates a C2 Beaconing session 10s later
        t1 = t0 + timedelta(seconds=10)
        det_c2 = make_dummy_detection_result(
            flow_id="flow_c2",
            threat_type=ThreatType.C2_BEACONING,
            src_ip="192.168.1.88",
            timestamp=t1,
        )
        alert_c2, is_new_c2 = self.correlator.process_detection(det_c2, timestamp=t1)
        self.assertTrue(is_new_c2)

        # Both alerts must be correlated into the same CorrelationGroup!
        self.assertEqual(alert_c2.correlation_group_id, group_id)
        corr_group = self.correlator.get_correlation_group(group_id)
        self.assertIsNotNone(corr_group)
        self.assertIn(alert_scan.alert_id, corr_group.alert_ids)
        self.assertIn(alert_c2.alert_id, corr_group.alert_ids)
        self.assertEqual(corr_group.key, "192.168.1.88")

    def test_max_signals_memory_bound(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        # Emit 25 repeated detections (limit is max_signals_per_alert=10)
        for i in range(25):
            t = t0 + timedelta(seconds=i * 0.5)
            det = make_dummy_detection_result(flow_id=f"flow_{i}", timestamp=t)
            alert, _ = self.correlator.process_detection(det, timestamp=t)

        self.assertLessEqual(len(alert.contributing_signals), 10)

    def test_alert_lifecycle_state_transitions(self) -> None:
        det = make_dummy_detection_result()
        alert, _ = self.correlator.process_detection(det)
        self.assertEqual(alert.status, AlertStatus.NEW)

        # Acknowledge
        ack_alert = self.correlator.acknowledge_alert(alert.alert_id)
        self.assertIsNotNone(ack_alert)
        self.assertEqual(ack_alert.status, AlertStatus.ACKNOWLEDGED)

        # Resolve
        res_alert = self.correlator.resolve_alert(alert.alert_id)
        self.assertIsNotNone(res_alert)
        self.assertEqual(res_alert.status, AlertStatus.RESOLVED)

    def test_suppression_cooldown(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        self.correlator.suppress_entity_threat("192.168.1.99", "SYN_FLOOD", duration_sec=60.0)

        # Detections during cooldown should be suppressed (None returned)
        det = make_dummy_detection_result(src_ip="192.168.1.99", timestamp=t0)
        suppressed_alert, is_new = self.correlator.process_detection(det, timestamp=t0)
        self.assertIsNone(suppressed_alert)
        self.assertFalse(is_new)

    def test_json_serialization_round_trip(self) -> None:
        det = make_dummy_detection_result()
        alert, _ = self.correlator.process_detection(det)

        json_str = alert.to_json()
        self.assertTrue(isinstance(json_str, str))

        reloaded = SecurityAlert.from_json(json_str)
        self.assertEqual(reloaded.alert_id, alert.alert_id)
        self.assertEqual(reloaded.threat_class, alert.threat_class)
        self.assertEqual(reloaded.numeric_risk_score, alert.numeric_risk_score)
        self.assertEqual(len(reloaded.evidence), len(alert.evidence))
        self.assertEqual(reloaded.source_ip, alert.source_ip)

    def test_prune_expired_clears_old_groups(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        det = make_dummy_detection_result(flow_id="f_old", timestamp=t0)
        self.correlator.process_detection(det, timestamp=t0)
        self.assertEqual(self.correlator.active_groups_count, 1)

        # Fast forward past time_window_sec (60s)
        t_future = t0 + timedelta(seconds=120)
        pruned_count = self.correlator.prune_expired(t_future)
        self.assertGreaterEqual(pruned_count, 1)
        self.assertEqual(self.correlator.active_groups_count, 0)

    def test_no_accidental_signal_loss(self) -> None:
        t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        sig1 = DetectionSignal(
            signal_id="sig_a1",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.RULE,
            detector_name="syn_rule",
            confidence=0.85,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="Rule sig",
        )
        sig2 = DetectionSignal(
            signal_id="sig_a2",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.ML,
            detector_name="syn_ml",
            confidence=0.88,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="ML sig",
        )
        det = make_dummy_detection_result(signals=[sig1, sig2], timestamp=t0)
        alert, _ = self.correlator.process_detection(det, timestamp=t0)

        # Verify all signals are faithfully preserved
        signal_ids = [s.signal_id for s in alert.contributing_signals]
        self.assertIn("sig_a1", signal_ids)
        self.assertIn("sig_a2", signal_ids)
        self.assertIn("RULE", alert.detector_types)
        self.assertIn("ML", alert.detector_types)

    def test_malformed_detection_handling(self) -> None:
        # Detection with empty context
        det = DetectionResult(
            detection_id="det_empty_ctx",
            flow_id="flow_empty",
            threat_type=ThreatType.UDP_FLOOD,
            detector_type=DetectorType.RULE,
            confidence=0.80,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            signals=[],
            context={},
        )
        # Should gracefully process without crashing, defaulting source_ip to 0.0.0.0
        alert, is_new = self.correlator.process_detection(det)
        self.assertTrue(is_new)
        self.assertEqual(alert.source_ip, "0.0.0.0")

    def test_deterministic_repeated_execution(self) -> None:
        calc = RiskCalculator()
        score1 = calc.calculate_risk(
            confidence=0.88,
            severity="HIGH",
            detector_types=["RULE", "ML"],
            signal_count=4,
            recurrence_count=2,
            time_delta_sec=15.0,
        )
        score2 = calc.calculate_risk(
            confidence=0.88,
            severity="HIGH",
            detector_types=["RULE", "ML"],
            signal_count=4,
            recurrence_count=2,
            time_delta_sec=15.0,
        )
        self.assertEqual(score1.score, score2.score)
        self.assertEqual(score1.breakdown, score2.breakdown)
        self.assertEqual(score1.explanation, score2.explanation)


class TestMitreMapper(unittest.TestCase):
    """Test static offline MITRE ATT&CK reference mapping."""

    def test_all_canonical_threats_mapped(self) -> None:
        for threat in [
            ThreatType.SYN_FLOOD,
            ThreatType.UDP_FLOOD,
            ThreatType.PORT_SCAN,
            ThreatType.C2_BEACONING,
            ThreatType.DNS_DGA,
            ThreatType.DNS_TUNNELING,
            ThreatType.SUSPICIOUS_TLS,
            ThreatType.DATA_EXFILTRATION,
            ThreatType.BEHAVIORAL_ANOMALY,
        ]:
            ref = MitreAttackMapper.get_mapping(threat)
            self.assertIsNotNone(ref, f"Threat {threat.value} should have MITRE mapping")
            self.assertTrue(ref.technique_id.startswith("T"))
            self.assertTrue(ref.tactic_id.startswith("TA"))

    def test_unmapped_threat_returns_none(self) -> None:
        ref = MitreAttackMapper.get_mapping(ThreatType.BENIGN)
        self.assertIsNone(ref)


if __name__ == "__main__":
    unittest.main()

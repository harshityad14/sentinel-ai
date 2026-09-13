"""Unit tests for SentinelAI 3-Layer Detection Architecture and Multi-Layer Fusion.

Verifies:
- Layer 1 (Random Forest ML) + Layer 3 (Deterministic Rule) agreement boost.
- Layer 2 (Isolation Forest Anomaly) unknown anomaly detection and cross-layer corroboration.
- Specialized rule threats (DNS_TUNNELING, DNS_DGA, SUSPICIOUS_TLS) preservation.
- Conservative false-positive handling: IF normal status never suppresses valid ML or rule alerts.
- End-to-end multi-layer detection pipeline execution.
"""

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

import unittest
from datetime import datetime, timezone
import uuid

from sentinel_detection.correlation.ensemble import EnsembleCorrelationEngine
from sentinel_detection.pipeline import create_default_detection_pipeline
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector
from tests.unit.test_detection import make_dummy_features, make_dummy_flow


class TestThreeLayerFusion(unittest.TestCase):
    def setUp(self):
        self.ensemble = EnsembleCorrelationEngine(
            min_consensus_confidence=0.50,
            agreement_bonus=0.10,
        )
        self.flow = make_dummy_flow()
        self.features = make_dummy_features()

    def test_no_signals_yields_benign(self):
        """When no layer produces a signal, ensemble returns clean BENIGN result."""
        result = self.ensemble.correlate(self.flow, self.features, [])
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.severity, DetectionSeverity.INFO)
        self.assertEqual(len(result.signals), 0)

    def test_layer1_layer3_agreement_boost(self):
        """Layer 1 (ML) + Layer 3 (Rule) agreeing on SYN_FLOOD yields agreement bonus."""
        sig_rule = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="SYNFloodRuleDetector",
            detector_type=DetectorType.RULE,
            threat_type=ThreatType.SYN_FLOOD,
            confidence=0.85,
            severity=DetectionSeverity.HIGH,
            evidence=[
                DetectionEvidence(
                    feature_name="net_packets_per_second",
                    observed_value=25000.0,
                    threshold_value=1000.0,
                    importance=1.0,
                    description="Excessive SYN rate",
                )
            ],
            description="SYN flood rule detected excessive SYN rate",
            timestamp=datetime.now(timezone.utc),
        )

        sig_ml = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.SYN_FLOOD,
            confidence=0.90,
            severity=DetectionSeverity.HIGH,
            evidence=[
                DetectionEvidence(
                    feature_name="net_packets_per_second",
                    observed_value=25000.0,
                    threshold_value=0.0,
                    importance=0.45,
                    description="Top predictive feature in RF",
                )
            ],
            description="Random Forest predicted SYN_FLOOD",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_rule, sig_ml])

        self.assertEqual(result.threat_type, ThreatType.SYN_FLOOD)
        self.assertEqual(result.detector_type, DetectorType.ENSEMBLE)
        # Agreement bonus applied: confidence > max(0.85, 0.90)
        self.assertGreater(result.confidence, 0.90)
        self.assertEqual(len(result.signals), 2)
        # Evidence from both detectors consolidated without crash
        self.assertGreaterEqual(len(result.evidence), 1)

    def test_layer3_specialized_rule_preserved(self):
        """Layer 3 specialized rule (DNS_TUNNELING) without ML coverage is fully preserved."""
        sig_dns = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="DNSTunnelingRuleDetector",
            detector_type=DetectorType.RULE,
            threat_type=ThreatType.DNS_TUNNELING,
            confidence=0.88,
            severity=DetectionSeverity.HIGH,
            evidence=[
                DetectionEvidence(
                    feature_name="dns_query_entropy",
                    observed_value=4.85,
                    threshold_value=3.80,
                    importance=0.9,
                    description="High Shannon entropy in DNS labels",
                )
            ],
            description="DNS tunneling detected via encoded high-entropy subdomain",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_dns])

        self.assertEqual(result.threat_type, ThreatType.DNS_TUNNELING)
        self.assertEqual(result.detector_type, DetectorType.RULE)
        self.assertEqual(result.confidence, 0.88)
        self.assertEqual(result.severity, DetectionSeverity.HIGH)

    def test_layer2_isolation_forest_unknown_anomaly(self):
        """Layer 2 alone flags out-of-distribution traffic as BEHAVIORAL_ANOMALY."""
        sig_if = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="IsolationForestAnomalyDetector",
            detector_type=DetectorType.STATISTICAL,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=0.78,
            severity=DetectionSeverity.MEDIUM,
            evidence=[
                DetectionEvidence(
                    feature_name="isolation_forest_anomaly_score",
                    observed_value=-0.145,
                    threshold_value=-0.042,
                    importance=0.78,
                    description="Decision score significantly below calibrated benign threshold",
                )
            ],
            description="Unsupervised anomaly detected (score=-0.1450, threshold=-0.0420)",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_if])

        self.assertEqual(result.threat_type, ThreatType.BEHAVIORAL_ANOMALY)
        self.assertEqual(result.detector_type, DetectorType.STATISTICAL)
        self.assertEqual(result.confidence, 0.78)

    def test_layer2_corroborates_layer1_attack(self):
        """Layer 2 anomaly corroboration boosts Layer 1 RF attack confidence."""
        sig_ml = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.PORT_SCAN,
            confidence=0.82,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="Random Forest predicted PORT_SCAN",
            timestamp=datetime.now(timezone.utc),
        )

        sig_if = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="IsolationForestAnomalyDetector",
            detector_type=DetectorType.STATISTICAL,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=0.75,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="Isolation Forest flagged flow as anomalous",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_ml, sig_if])

        # Attack classification preserved as PORT_SCAN
        self.assertEqual(result.threat_type, ThreatType.PORT_SCAN)
        # Corroborated confidence is boosted above raw RF confidence
        self.assertGreater(result.confidence, 0.82)

    def test_conservative_no_alert_suppression(self):
        """When ML detects an attack but IF does NOT fire, the ML alert is NEVER suppressed."""
        sig_ml = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.C2_BEACONING,
            confidence=0.72,
            severity=DetectionSeverity.MEDIUM,
            evidence=[
                DetectionEvidence(
                    feature_name="time_jitter_ratio",
                    observed_value=0.015,
                    threshold_value=0.0,
                    importance=0.35,
                    description="Periodic beaconing timing",
                )
            ],
            description="RF predicted C2_BEACONING",
            timestamp=datetime.now(timezone.utc),
        )

        # IF did not emit any signal (considered normal) -> only sig_ml passed
        result = self.ensemble.correlate(self.flow, self.features, [sig_ml])

        self.assertEqual(result.threat_type, ThreatType.C2_BEACONING)
        self.assertEqual(result.confidence, 0.72)
        self.assertEqual(result.severity, DetectionSeverity.MEDIUM)

    def test_validation_only_threshold_loading(self):
        """Verify RF detector loads validation-only class thresholds and provenance."""
        from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
        rf_detector = RandomForestMLDetector()
        self.assertIsNotNone(rf_detector.metadata)
        self.assertTrue(hasattr(rf_detector.metadata, "class_thresholds"))
        thresholds = getattr(rf_detector.metadata, "class_thresholds", {})
        self.assertIn("C2_BEACONING", thresholds)
        self.assertIn("BEHAVIORAL_ANOMALY", thresholds)
        self.assertIn("SYN_FLOOD", thresholds)
        self.assertGreaterEqual(thresholds["C2_BEACONING"], 0.90)

        provenance = getattr(rf_detector.metadata, "calibration_provenance", {})
        self.assertIn("methodology", provenance)
        self.assertIn("zero holdout", provenance["methodology"].lower())

    def test_threshold_rejection_of_borderline_rf_predictions(self):
        """Uncorroborated borderline RF prediction is retained as LOW severity investigation signal."""
        sig_borderline = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.C2_BEACONING,
            confidence=0.62,
            severity=DetectionSeverity.LOW,
            evidence=[],
            description="ML classifier predicted C2_BEACONING with 62.0% confidence [BORDERLINE]",
            metadata={
                "is_borderline": True,
                "calibrated_threshold": 0.98,
                "model_version": "3.0.0",
            },
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_borderline])
        self.assertEqual(result.threat_type, ThreatType.C2_BEACONING)
        self.assertEqual(result.severity, DetectionSeverity.LOW)
        self.assertIn("investigation signal", result.explanation.lower())

    def test_borderline_rf_corroborated_by_if(self):
        """Borderline RF prediction corroborated by IF anomaly is elevated to confirmed alert."""
        sig_borderline = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.C2_BEACONING,
            confidence=0.65,
            severity=DetectionSeverity.LOW,
            evidence=[],
            description="ML classifier predicted C2_BEACONING with 65.0% confidence [BORDERLINE]",
            metadata={
                "is_borderline": True,
                "calibrated_threshold": 0.98,
                "model_version": "3.0.0",
            },
            timestamp=datetime.now(timezone.utc),
        )

        sig_if = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="IsolationForestAnomalyDetector",
            detector_type=DetectorType.STATISTICAL,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=0.75,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="Isolation Forest detected out-of-distribution traffic",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_borderline, sig_if])
        self.assertEqual(result.threat_type, ThreatType.C2_BEACONING)
        self.assertGreater(result.confidence, 0.65)
        self.assertIn("isolation forest anomaly corroboration", result.explanation.lower())

    def test_rf_plus_rule_plus_if_triple_corroboration(self):
        """RF + Rule + IF anomaly produces maximum corroboration across all 3 layers."""
        sig_rule = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="SYNFloodRuleDetector",
            detector_type=DetectorType.RULE,
            threat_type=ThreatType.SYN_FLOOD,
            confidence=0.85,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="SYN flood rule fired",
            timestamp=datetime.now(timezone.utc),
        )
        sig_ml = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.SYN_FLOOD,
            confidence=0.88,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="RF predicted SYN_FLOOD",
            timestamp=datetime.now(timezone.utc),
        )
        sig_if = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="IsolationForestAnomalyDetector",
            detector_type=DetectorType.STATISTICAL,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=0.80,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="IF anomaly fired",
            timestamp=datetime.now(timezone.utc),
        )

        result = self.ensemble.correlate(self.flow, self.features, [sig_rule, sig_ml, sig_if])
        self.assertEqual(result.threat_type, ThreatType.SYN_FLOOD)
        self.assertEqual(result.detector_type, DetectorType.ENSEMBLE)
        self.assertGreater(result.confidence, 0.90)
        self.assertIn("RF+Rule agreement", result.explanation)
        self.assertIn("Isolation Forest anomaly corroboration", result.explanation)

    def test_minority_class_anti_amplification(self):
        """Minority RF prediction is not amplified merely because other detectors are silent."""
        sig_ml = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.DATA_EXFILTRATION,
            confidence=0.60,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="RF predicted DATA_EXFILTRATION",
            metadata={"is_borderline": False, "calibrated_threshold": 0.59},
            timestamp=datetime.now(timezone.utc),
        )

        # Single detector: confidence must NOT receive agreement bonus
        result = self.ensemble.correlate(self.flow, self.features, [sig_ml])
        self.assertEqual(result.threat_type, ThreatType.DATA_EXFILTRATION)
        self.assertEqual(result.confidence, 0.60)
        self.assertEqual(result.detector_type, DetectorType.ML)

    def test_normal_if_never_suppresses_rules(self):
        """Normal IF status (no IF signal) never vetoes or degrades high-confidence rule alert."""
        sig_rule = DetectionSignal(
            signal_id=f"sig_{uuid.uuid4().hex[:8]}",
            flow_id=self.flow.flow_id,
            detector_name="DNSDGARuleDetector",
            detector_type=DetectorType.RULE,
            threat_type=ThreatType.DNS_DGA,
            confidence=0.92,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="DGA algorithm detected",
            timestamp=datetime.now(timezone.utc),
        )

        # No IF signal present (normal IF)
        result = self.ensemble.correlate(self.flow, self.features, [sig_rule])
        self.assertEqual(result.threat_type, ThreatType.DNS_DGA)
        self.assertEqual(result.confidence, 0.92)
        self.assertEqual(result.severity, DetectionSeverity.HIGH)
        self.assertEqual(result.detector_type, DetectorType.RULE)

    def test_deterministic_behavior(self):
        """Ensemble correlation produces 100% identical outputs for identical inputs."""
        sig_ml = DetectionSignal(
            signal_id="sig-det-1",
            flow_id=self.flow.flow_id,
            detector_name="RandomForestMLDetector",
            detector_type=DetectorType.ML,
            threat_type=ThreatType.PORT_SCAN,
            confidence=0.85,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="Port scan detected",
            timestamp=datetime(2026, 9, 13, 0, 0, 0, tzinfo=timezone.utc),
        )
        sig_if = DetectionSignal(
            signal_id="sig-det-2",
            flow_id=self.flow.flow_id,
            detector_name="IsolationForestAnomalyDetector",
            detector_type=DetectorType.STATISTICAL,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=0.70,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="IF anomaly detected",
            timestamp=datetime(2026, 9, 13, 0, 0, 0, tzinfo=timezone.utc),
        )

        res1 = self.ensemble.correlate(self.flow, self.features, [sig_ml, sig_if])
        res2 = self.ensemble.correlate(self.flow, self.features, [sig_ml, sig_if])

        self.assertEqual(res1.threat_type, res2.threat_type)
        self.assertEqual(res1.confidence, res2.confidence)
        self.assertEqual(res1.severity, res2.severity)
        self.assertEqual(res1.explanation, res2.explanation)

    def test_metadata_serialization_deserialization(self):
        """Model metadata serializes and deserializes class_thresholds and calibration provenance."""
        from sentinel_detection.ml.model_metadata import MLModelMetadata
        meta = MLModelMetadata(
            model_name="test_meta",
            model_version="1.0.0",
            algorithm="RandomForestClassifier",
            feature_version="1.0",
            feature_names=["f1", "f2"],
            target_classes=["BENIGN", "PORT_SCAN"],
            class_thresholds={"PORT_SCAN": 0.75},
            calibration_provenance={"methodology": "validation-only grid search", "samples": 1000},
        )
        json_str = meta.model_dump_json()
        deserialized = MLModelMetadata.model_validate_json(json_str)
        self.assertEqual(deserialized.class_thresholds, {"PORT_SCAN": 0.75})
        self.assertEqual(deserialized.calibration_provenance["samples"], 1000)

    def test_default_pipeline_runs_all_layers_safely(self):
        """Verify default pipeline with all 3 layers processes normal and attack flows safely."""
        pipeline = create_default_detection_pipeline()

        # 1. Normal benign flow
        benign_flow = make_dummy_flow()
        benign_feat = make_dummy_features(bps=500.0, total_bytes=800, total_packets=8)
        res_benign = pipeline.analyze(benign_flow, benign_feat)
        self.assertIsNotNone(res_benign)
        self.assertEqual(res_benign.threat_type, ThreatType.BENIGN)

        # 2. Extreme SYN flood flow (triggers rule and ML)
        flood_flow = make_dummy_flow(protocol=ProtocolType.TCP)
        flood_feat = make_dummy_features(
            pps=30000.0,
            bps=1500000.0,
            total_packets=30000,
            total_bytes=1500000,
            syn_count=30000,
            ack_count=1,
        )
        res_flood = pipeline.analyze(flood_flow, flood_feat)
        self.assertIsNotNone(res_flood)
        self.assertIn(
            res_flood.threat_type,
            [ThreatType.SYN_FLOOD, ThreatType.BEHAVIORAL_ANOMALY],
        )
        self.assertGreater(res_flood.confidence, 0.50)


if __name__ == "__main__":
    unittest.main()



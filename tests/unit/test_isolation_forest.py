"""Unit tests for SentinelAI Layer 2 Isolation Forest Anomaly Detector."""

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

import tempfile
import unittest
import numpy as np

from sentinel_detection.ml.isolation_forest_detector import (
    IsolationForestAnomalyDetector,
    create_deterministic_if_baseline,
)
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_detection.ml.trainer_isolation_forest import (
    build_if_model_artifacts,
    evaluate_isolation_forest,
    save_if_artifacts,
    train_isolation_forest,
)
from sentinel_models.detection import DetectorType, ThreatType
from tests.unit.test_detection import make_dummy_features, make_dummy_flow


class TestIsolationForestAnomalyDetector(unittest.TestCase):
    def test_fallback_baseline_initialization(self):
        """Verify deterministic fallback baseline initializes without crashing and has expected metadata."""
        detector = IsolationForestAnomalyDetector()
        self.assertTrue(detector.enabled)
        self.assertEqual(detector.detector_type, DetectorType.STATISTICAL)
        self.assertEqual(detector.threat_type, ThreatType.BEHAVIORAL_ANOMALY)
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.metadata)
        self.assertEqual(detector.metadata.algorithm, "IsolationForest")
        self.assertEqual(detector.metadata.feature_names, CANONICAL_ML_FEATURES)

    def test_fallback_normal_flow_not_flagged(self):
        """Verify typical normal web flow is not falsely flagged by baseline."""
        detector = IsolationForestAnomalyDetector()
        flow = make_dummy_flow()
        features = make_dummy_features(bps=1000.0, total_bytes=1000)
        signal = detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_training_and_threshold_calibration(self):
        """Verify training strictly on benign samples and calibrating threshold."""
        rng = np.random.RandomState(42)
        X_benign = rng.normal(loc=10.0, scale=1.0, size=(200, 15))

        clf, info = train_isolation_forest(X_benign, random_state=42, calibration_quantile=0.02)
        self.assertIsNotNone(clf)
        self.assertIn("calibrated_threshold", info)
        self.assertIn("training_time_sec", info)
        self.assertGreater(info["training_time_sec"], 0.0)

        # Test holdout evaluation
        X_test_benign = rng.normal(loc=10.0, scale=1.0, size=(100, 15))
        X_test_attack = rng.normal(loc=100.0, scale=10.0, size=(50, 15))
        X_test = np.vstack([X_test_benign, X_test_attack])
        y_test = np.array(["BENIGN"] * 100 + ["SYN_FLOOD"] * 50)

        metrics = evaluate_isolation_forest(
            clf, X_test, y_test, calibrated_threshold=info["calibrated_threshold"]
        )

        self.assertIn("anomaly_precision", metrics)
        self.assertIn("anomaly_recall", metrics)
        self.assertIn("benign_false_positive_rate", metrics)
        self.assertIn("performance", metrics)
        self.assertGreater(metrics["anomaly_recall"], 0.80)  # Distinct outliers easily isolated
        self.assertLess(metrics["benign_false_positive_rate"], 0.10)

    def test_serialization_and_reloading(self):
        """Test serializing Isolation Forest model and metadata and reloading into detector."""
        rng = np.random.RandomState(42)
        X_train = rng.normal(loc=5.0, scale=1.0, size=(100, 15))
        clf, info = train_isolation_forest(X_train, random_state=42)

        dataset_meta = {"source": "unit_test", "samples": len(X_train)}
        metrics = {"calibrated_threshold": info["calibrated_threshold"]}

        model, metadata = build_if_model_artifacts(
            model=clf,
            metrics=metrics,
            dataset_metadata=dataset_meta,
            model_name="sentinel_if_test",
            model_version="1.0.0-test",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            m_file, meta_file = save_if_artifacts(model, metadata, tmp_dir)
            self.assertTrue(m_file.exists())
            self.assertTrue(meta_file.exists())

            # Load into detector
            detector = IsolationForestAnomalyDetector(model_path=m_file, metadata_path=meta_file)
            self.assertEqual(detector.metadata.model_name, "sentinel_if_test")
            self.assertEqual(detector.threshold, info["calibrated_threshold"])


if __name__ == "__main__":
    unittest.main()

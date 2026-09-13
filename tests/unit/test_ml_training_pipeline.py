"""Unit tests for SentinelAI Phase 10 Random Forest training, evaluation, and serialization pipeline."""

from pathlib import Path
import tempfile
import unittest
import numpy as np

from sentinel_detection.ml.data_loader import (
    balance_dataset,
    create_train_test_split,
    load_dataset_from_csv,
)
from sentinel_detection.ml.dataset_adapter import CICDatasetAdapter
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES, create_deterministic_baseline_model
from sentinel_detection.ml.trainer_v2 import (
    build_trained_model_artifacts,
    evaluate_model,
    save_trained_artifacts,
    train_random_forest,
)


class TestMLTrainingPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_dataset = Path("data/samples/cic_ids_curated_sample.csv")
        if not cls.sample_dataset.exists():
            raise FileNotFoundError(f"Fixture not found: {cls.sample_dataset}")

    def test_load_dataset(self):
        """Test loading dataset from CSV via CIC adapter."""
        X, y, feature_names = load_dataset_from_csv(self.sample_dataset, adapter=CICDatasetAdapter())
        self.assertGreater(len(X), 50)
        self.assertEqual(len(X), len(y))
        self.assertEqual(X.shape[1], 15)
        self.assertEqual(feature_names, CANONICAL_ML_FEATURES)

        # Check no NaN or Inf in feature matrix
        self.assertFalse(np.isnan(X).any(), "X contains NaN values")
        self.assertFalse(np.isinf(X).any(), "X contains Inf values")

    def test_balance_dataset(self):
        """Test balancing dataset preserves minority attacks while controlling benign ratio."""
        X = np.ones((100, 15))
        y = np.array(["BENIGN"] * 80 + ["PORT_SCAN"] * 10 + ["SYN_FLOOD"] * 10)

        X_bal, y_bal = balance_dataset(X, y, benign_ratio=0.70, random_state=42)
        n_benign = np.sum(y_bal == "BENIGN")
        n_attack = np.sum(y_bal != "BENIGN")

        self.assertEqual(n_attack, 20)  # Attacks must not be discarded
        self.assertLessEqual(n_benign, 80)
        self.assertGreater(n_benign, 0)

    def test_stratified_split(self):
        """Test train/test split maintains class stratification deterministically."""
        X, y, _ = load_dataset_from_csv(self.sample_dataset, adapter=CICDatasetAdapter())
        X_train, X_test, y_train, y_test = create_train_test_split(X, y, test_size=0.20, random_state=42)

        self.assertEqual(len(X_train) + len(X_test), len(X))
        # Every class should be present in both train and test splits
        self.assertEqual(set(y_train), set(y_test))

    def test_training_and_evaluation(self):
        """Test training and rigorous evaluation without hard-coded numbers."""
        X, y, feats = load_dataset_from_csv(self.sample_dataset, adapter=CICDatasetAdapter())
        X_train, X_test, y_train, y_test = create_train_test_split(X, y, test_size=0.25, random_state=42)

        clf, training_info = train_random_forest(X_train, y_train, random_state=42)
        self.assertIsNotNone(clf)
        self.assertIn("training_time_sec", training_info)
        self.assertGreater(training_info["training_time_sec"], 0.0)

        metrics = evaluate_model(clf, X_test, y_test, feature_names=feats)

        # Check required evaluation keys
        required_keys = [
            "overall_accuracy",
            "macro_f1",
            "weighted_f1",
            "macro_precision",
            "macro_recall",
            "benign_false_positive_rate",
            "classes",
            "confusion_matrix",
            "per_class",
            "feature_importances",
            "performance",
        ]
        for k in required_keys:
            self.assertIn(k, metrics, f"Missing metric key: {k}")

        # Metrics must be within legitimate mathematical bounds [0.0, 1.0]
        self.assertGreaterEqual(metrics["overall_accuracy"], 0.0)
        self.assertLessEqual(metrics["overall_accuracy"], 1.0)
        self.assertGreaterEqual(metrics["macro_f1"], 0.0)
        self.assertLessEqual(metrics["macro_f1"], 1.0)
        self.assertGreaterEqual(metrics["benign_false_positive_rate"], 0.0)
        self.assertLessEqual(metrics["benign_false_positive_rate"], 1.0)

        # Performance metrics
        perf = metrics["performance"]
        self.assertGreater(perf["throughput_flows_sec"], 10.0)
        self.assertGreater(perf["mean_latency_ms"], 0.0)

    def test_artifact_serialization_and_deserialization(self):
        """Test end-to-end model saving, metadata serialization, and detector loading."""
        X, y, feats = load_dataset_from_csv(self.sample_dataset, adapter=CICDatasetAdapter())
        X_train, X_test, y_train, y_test = create_train_test_split(X, y, test_size=0.20, random_state=42)

        clf, _ = train_random_forest(X_train, y_train, random_state=42)
        metrics = evaluate_model(clf, X_test, y_test, feature_names=feats)

        dataset_meta = {
            "source_dataset": "test_sample.csv",
            "source_sha256": "dummy_sha",
            "total_records": len(X),
        }

        model, metadata = build_trained_model_artifacts(
            model=clf,
            metrics=metrics,
            dataset_metadata=dataset_meta,
            model_name="sentinel_test_rf",
            model_version="1.0.0-test",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            model_file, meta_file = save_trained_artifacts(model, metadata, tmp_dir)
            self.assertTrue(model_file.exists())
            self.assertTrue(meta_file.exists())

            # Load back through RandomForestMLDetector
            detector = RandomForestMLDetector(
                model_path=model_file,
                metadata_path=meta_file,
            )

            self.assertEqual(detector.detector_name, "ml_sentinel_test_rf")
            self.assertEqual(detector.metadata.model_version, "1.0.0-test")
            self.assertEqual(detector.metadata.target_classes, clf.classes_.tolist())

    def test_production_model_or_fallback_loaded(self):
        """Ensure default detector loads either the production model or deterministic fallback without failing."""
        detector = RandomForestMLDetector()
        self.assertTrue(detector.enabled)
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.metadata)
        self.assertEqual(len(detector.metadata.feature_names), 15)
        self.assertEqual(detector.metadata.feature_names, CANONICAL_ML_FEATURES)


if __name__ == "__main__":
    unittest.main()

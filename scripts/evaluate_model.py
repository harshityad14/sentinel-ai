"""CLI utility to evaluate a trained SentinelAI Random Forest model against a dataset.

Supports cross-environment external evaluation on UNSW-NB15 as well as CIC-IDS test datasets.
All metrics are purely measured from prediction outputs.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict
import joblib

# Ensure packages are importable when running script directly
project_root = Path(__file__).resolve().parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from sentinel_detection.ml.data_loader import load_dataset_from_csv
from sentinel_detection.ml.dataset_adapter import CICDatasetAdapter, UNSWDatasetAdapter
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_detection.ml.trainer_v2 import evaluate_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.evaluate_model")


def print_evaluation_summary(metrics: Dict, dataset_name: str, model_info: str) -> None:
    print("\n" + "=" * 70)
    print(f"       EXTERNAL VALIDATION REPORT: {dataset_name.upper()}")
    print(f"       Model: {model_info}")
    print("=" * 70)
    print(f"Overall Accuracy:           {metrics['overall_accuracy']:.4f} ({metrics['overall_accuracy'] * 100:.2f}%)")
    print(f"Macro F1 Score:             {metrics['macro_f1']:.4f}")
    print(f"Weighted F1 Score:          {metrics['weighted_f1']:.4f}")
    print(f"Macro Precision:            {metrics['macro_precision']:.4f}")
    print(f"Macro Recall:               {metrics['macro_recall']:.4f}")
    print(f"Benign False Positive Rate: {metrics['benign_false_positive_rate']:.4f} ({metrics['benign_false_positive_rate'] * 100:.2f}%)")
    print(f"Mean Inference Latency:     {metrics['performance']['mean_latency_ms']:.4f} ms/flow")
    print(f"Single-Core Throughput:     {metrics['performance']['throughput_flows_sec']:.1f} flows/sec")
    print("-" * 70)
    print("Per-Class Metrics:")
    print(f"{'Class':<22} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'FPR':<8} {'Support':<8}")
    print("-" * 70)
    for cls_name, pcm in metrics["per_class"].items():
        print(f"{cls_name:<22} {pcm['precision']:<10.4f} {pcm['recall']:<10.4f} {pcm['f1_score']:<10.4f} {pcm['false_positive_rate']:<8.4f} {pcm['support']:<8}")
    print("-" * 70)
    print("Confusion Matrix (Classes: " + ", ".join(metrics["classes"]) + "):")
    for row in metrics["confusion_matrix"]:
        print("  " + str(row))
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SentinelAI Random Forest model against a dataset.")
    parser.add_argument(
        "--model",
        type=str,
        default="packages/detection/sentinel_detection/ml/models/sentinel_rf_production.joblib",
        help="Path to trained .joblib model file",
    )
    parser.add_argument(
        "--metadata",
        type=str,
        default=None,
        help="Optional path to model .json metadata file",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to evaluation CSV dataset",
    )
    parser.add_argument(
        "--dataset-type",
        type=str,
        choices=["cic", "unsw"],
        default="unsw",
        help="Adapter type for dataset schema ('cic' or 'unsw')",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Optional maximum samples to evaluate",
    )
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        logger.error(f"Model file not found: {model_path}")
        sys.exit(1)

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        logger.error(f"Dataset file not found: {dataset_path}")
        sys.exit(1)

    # 1. Load model
    logger.info(f"Loading trained model from {model_path}...")
    clf = joblib.load(model_path)

    # 2. Select adapter
    if args.dataset_type == "unsw":
        adapter = UNSWDatasetAdapter()
    else:
        adapter = CICDatasetAdapter()

    # 3. Load and adapt dataset
    logger.info(f"Loading and adapting evaluation dataset from {dataset_path} with {adapter.__class__.__name__}...")
    X, y, feature_names = load_dataset_from_csv(dataset_path, adapter=adapter, max_samples=args.max_samples)

    # 4. Filter or align to model classes if needed
    model_classes = set(clf.classes_)
    dataset_classes = set(y)
    unsupported = dataset_classes - model_classes
    if unsupported:
        logger.warning(f"Dataset contains classes not recognized by model: {unsupported}. Filtering them out.")
        mask = [label in model_classes for label in y]
        X = X[mask]
        y = y[mask]

    # 5. Execute evaluation
    metrics = evaluate_model(clf, X, y, feature_names=feature_names)
    print_evaluation_summary(metrics, dataset_name=dataset_path.name, model_info=model_path.name)


if __name__ == "__main__":
    main()

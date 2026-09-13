"""CLI utility to train, evaluate, and serialize SentinelAI Random Forest detection model.

Uses strictly canonical 15-feature vectors and deterministic hyperparameters.
Persists model (.joblib) and measured metadata (.json) with zero synthetic/hard-coded metrics.
"""

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Dict

# Ensure packages are importable when running script directly
project_root = Path(__file__).resolve().parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from sentinel_detection.ml.data_loader import (
    balance_dataset,
    create_train_test_split,
    load_dataset_from_csv,
)
from sentinel_detection.ml.dataset_adapter import CICDatasetAdapter
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_detection.ml.trainer_v2 import (
    build_trained_model_artifacts,
    evaluate_model,
    save_trained_artifacts,
    train_random_forest,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.train_model")


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def print_evaluation_summary(metrics: Dict) -> None:
    print("\n" + "=" * 70)
    print("           SENTINELAI ML MODEL EVALUATION RESULTS (MEASURED)")
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
    print("-" * 70)
    print("Top Feature Importances:")
    for feat, imp in list(metrics["feature_importances"].items())[:7]:
        print(f"  {feat:<30}: {imp:.4f} ({imp * 100:.1f}%)")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate SentinelAI Random Forest classifier.")
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/samples/cic_ids_curated_sample.csv",
        help="Path to CSV dataset for training",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="packages/detection/sentinel_detection/ml/models",
        help="Directory to save model artifacts",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="sentinel_rf_production",
        help="Artifact filename base",
    )
    parser.add_argument(
        "--model-version",
        type=str,
        default="2.0.0",
        help="Model semantic version",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        help="Test split fraction",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Deterministic RNG seed",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Optional maximum samples to load",
    )
    parser.add_argument(
        "--balance-benign",
        action="store_true",
        help="Subsample majority benign class to match operational distribution (85% benign)",
    )
    args = parser.parse_args()

    data_path = Path(args.dataset)
    if not data_path.exists():
        logger.error(f"Dataset path does not exist: {data_path}")
        sys.exit(1)

    # 1. Load data
    logger.info(f"Loading dataset from {data_path}...")
    X, y, feature_names = load_dataset_from_csv(
        data_path,
        adapter=CICDatasetAdapter(),
        max_samples=args.max_samples,
    )

    # Optional class balancing
    if args.balance_benign:
        X, y = balance_dataset(X, y, benign_ratio=0.85, random_state=args.random_state)

    # 2. Stratified train/test split
    logger.info(f"Splitting dataset (test_size={args.test_size}, random_state={args.random_state})...")
    X_train, X_test, y_train, y_test = create_train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state
    )

    # 3. Train Random Forest
    clf, training_info = train_random_forest(
        X_train, y_train, random_state=args.random_state
    )

    # 4. Measure evaluation metrics
    metrics = evaluate_model(clf, X_test, y_test, feature_names=feature_names)
    print_evaluation_summary(metrics)

    # 5. Build metadata
    dataset_metadata = {
        "source_dataset": data_path.name,
        "source_sha256": compute_file_sha256(data_path),
        "total_records": int(len(X)),
        "train_records": int(len(X_train)),
        "test_records": int(len(X_test)),
        "classes_count": len(set(y)),
    }

    model, metadata = build_trained_model_artifacts(
        model=clf,
        metrics=metrics,
        dataset_metadata=dataset_metadata,
        model_name=args.model_name,
        model_version=args.model_version,
        feature_names=feature_names,
    )

    # 6. Save artifacts
    out_dir = Path(args.output)
    model_file, meta_file = save_trained_artifacts(model, metadata, out_dir)
    logger.info(f"Model successfully saved to {model_file}")
    logger.info(f"Metadata successfully saved to {meta_file}")


if __name__ == "__main__":
    main()

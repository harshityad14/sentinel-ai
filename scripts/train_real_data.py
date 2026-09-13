"""Train SentinelAI Random Forest on real CIC-IDS2017 dataset with per-file chronological splitting.

Per-file chronological split strategy (reduces temporal leakage while ensuring class coverage):
  For EACH CSV file: first 80% of rows -> TRAIN, last 20% -> TEST

This preserves temporal ordering within each capture session while ensuring all
attack types appear in both train and test splits (unlike day-level splitting,
which isolates attack types by day in CIC-IDS2017).

Handles:
- Multi-file loading with progress reporting
- Unicode replacement character labels (Web Attack labels)
- Class-balanced subsampling for memory efficiency
- NaN/Inf sanitization via CICDatasetAdapter
- Deterministic random_state=42
"""

import argparse
import collections
import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np

# Ensure packages are importable
project_root = Path(__file__).resolve().parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from sentinel_detection.ml.data_loader import load_dataset_from_csv
from sentinel_detection.ml.dataset_adapter import CICDatasetAdapter
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_detection.ml.trainer_isolation_forest import (
    build_if_model_artifacts,
    evaluate_isolation_forest,
    save_if_artifacts,
    train_isolation_forest,
)
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
logger = logging.getLogger("sentinel.train_real_data")


def find_csv_files(dataset_dir: Path) -> List[Path]:
    """Find all CSV files in the dataset directory."""
    return sorted(dataset_dir.glob("*.csv"))


def load_and_split_csv(
    file_path: Path,
    adapter: CICDatasetAdapter,
    train_fraction: float = 0.80,
    max_samples: Optional[int] = None,
    return_metadata: bool = False,
) -> Union[
    Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray],
    Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, Dict[str, np.ndarray], Dict[str, np.ndarray]],
]:
    """Load a single CSV file and split each threat class chronologically (first N% train, rest test).

    Session-aware / attack-aware chronological split strategy:
      Within each capture session file, for each distinct threat class (and benign):
      - First 80% of chronological occurrences -> TRAIN
      - Last 20% of chronological occurrences -> TEST

    Guarantees:
      - Zero temporal leakage: within every class and file, test samples are strictly later in time.
      - Full class coverage: every attack session in the file is represented in both splits.
      - Zero sample fabrication or duplication: all test samples are 100% genuine holdout flows.
    """
    if return_metadata:
        X, y, _, meta = load_dataset_from_csv(
            file_path, adapter=adapter, max_samples=max_samples, return_metadata=True
        )
    else:
        X, y, _ = load_dataset_from_csv(file_path, adapter=adapter, max_samples=max_samples)

    tr_indices = []
    te_indices = []
    classes = np.unique(y)

    for c in classes:
        c_idx = np.where(y == c)[0]
        n_c = len(c_idx)
        split = int(n_c * train_fraction)
        if split == n_c and n_c > 1:
            split = n_c - 1
        elif split == 0 and n_c > 1:
            split = 1
        tr_indices.extend(c_idx[:split])
        te_indices.extend(c_idx[split:])

    tr_indices = np.sort(tr_indices)
    te_indices = np.sort(te_indices)

    if return_metadata:
        meta_tr = {k: v[tr_indices] for k, v in meta.items()}
        meta_te = {k: v[te_indices] for k, v in meta.items()}
        return X[tr_indices], y[tr_indices], X[te_indices], y[te_indices], meta_tr, meta_te

    return X[tr_indices], y[tr_indices], X[te_indices], y[te_indices]


def subsample_balanced(
    X: np.ndarray,
    y: np.ndarray,
    max_total: int = 400000,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Subsample to max_total while preserving class representation.

    Strategy:
    1. For each minority class (< max_total/n_classes), keep ALL samples
    2. Subsample majority classes proportionally with remaining budget
    """
    rng = np.random.RandomState(random_state)
    classes, counts = np.unique(y, return_counts=True)
    n_classes = len(classes)

    if len(X) <= max_total:
        logger.info(f"Dataset ({len(X)} samples) fits within max_total ({max_total}), no subsampling needed.")
        return X, y

    per_class_base = max_total // n_classes

    selected_indices = []
    remaining_budget = max_total
    large_classes = []

    for cls, cnt in zip(classes, counts):
        if cnt <= per_class_base:
            indices = np.where(y == cls)[0]
            selected_indices.append(indices)
            remaining_budget -= cnt
        else:
            large_classes.append((cls, cnt))

    if large_classes and remaining_budget > 0:
        total_large = sum(cnt for _, cnt in large_classes)
        for cls, cnt in large_classes:
            allocation = int(remaining_budget * (cnt / total_large))
            allocation = min(allocation, cnt)
            allocation = max(allocation, 1)
            indices = np.where(y == cls)[0]
            chosen = rng.choice(indices, size=allocation, replace=False)
            selected_indices.append(chosen)

    combined = np.concatenate(selected_indices)
    rng.shuffle(combined)

    logger.info(f"Subsampled from {len(X)} to {len(combined)} samples")
    return X[combined], y[combined]


def compute_dir_hash(files: List[Path]) -> str:
    """Compute hash of dataset file names and sizes for reproducibility tracking."""
    h = hashlib.sha256()
    for f in sorted(files):
        h.update(f.name.encode())
        h.update(str(f.stat().st_size).encode())
    return h.hexdigest()[:16]


def print_evaluation_summary(metrics: Dict, split_name: str = "TEST") -> None:
    print(f"\n{'=' * 70}")
    print(f"    SENTINELAI ML EVALUATION - {split_name} SPLIT (MEASURED)")
    print(f"{'=' * 70}")
    print(f"Overall Accuracy:           {metrics['overall_accuracy']:.4f} ({metrics['overall_accuracy'] * 100:.2f}%)")
    print(f"Macro F1 Score:             {metrics['macro_f1']:.4f}")
    print(f"Weighted F1 Score:          {metrics['weighted_f1']:.4f}")
    print(f"Macro Precision:            {metrics['macro_precision']:.4f}")
    print(f"Macro Recall:               {metrics['macro_recall']:.4f}")
    print(f"Benign False Positive Rate: {metrics['benign_false_positive_rate']:.4f} ({metrics['benign_false_positive_rate'] * 100:.2f}%)")
    if "batch_mean_latency_ms" in metrics["performance"]:
        print(f"Batch Mean Latency:             {metrics['performance']['batch_mean_latency_ms']:.4f} ms/flow")
        print(f"Batch Vectorized Throughput:    {metrics['performance']['batch_throughput_flows_sec']:.1f} flows/sec")
    if "p50_latency_ms" in metrics["performance"]:
        print(f"Single-Flow Mean Latency:       {metrics['performance']['single_flow_mean_latency_ms']:.4f} ms/flow")
        print(f"Single-Flow P50 Latency:        {metrics['performance']['p50_latency_ms']:.4f} ms/flow")
        print(f"Single-Flow P95 Latency:        {metrics['performance']['p95_latency_ms']:.4f} ms/flow")
        print(f"Single-Flow P99 Latency:        {metrics['performance']['p99_latency_ms']:.4f} ms/flow")
        print(f"Single-Flow Serial Throughput:  {metrics['performance']['single_flow_throughput_flows_sec']:.1f} flows/sec")
    print(f"{'-' * 70}")
    print(f"{'Class':<22} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'FPR':<8} {'Support':<8}")
    print(f"{'-' * 70}")
    for cls_name, pcm in metrics["per_class"].items():
        print(f"{cls_name:<22} {pcm['precision']:<10.4f} {pcm['recall']:<10.4f} {pcm['f1_score']:<10.4f} {pcm['false_positive_rate']:<8.4f} {pcm['support']:<8}")
    print(f"{'-' * 70}")
    print("Confusion Matrix (Classes: " + ", ".join(metrics["classes"]) + "):")
    for row in metrics["confusion_matrix"]:
        print("  " + str(row))
    print(f"{'-' * 70}")
    print("Top Feature Importances:")
    for feat, imp in list(metrics["feature_importances"].items())[:7]:
        print(f"  {feat:<30}: {imp:.4f} ({imp * 100:.1f}%)")
    print(f"{'=' * 70}\n")


def print_if_evaluation_summary(metrics: Dict, split_name: str = "TEST (ISOLATION FOREST)") -> None:
    print(f"\n{'=' * 70}")
    print(f"    SENTINELAI ISOLATION FOREST - {split_name} (MEASURED)")
    print(f"{'=' * 70}")
    print(f"Anomaly Precision:          {metrics['anomaly_precision']:.4f}")
    print(f"Anomaly Recall:             {metrics['anomaly_recall']:.4f}")
    print(f"Anomaly F1 Score:           {metrics['anomaly_f1']:.4f}")
    print(f"Benign False Positive Rate: {metrics['benign_false_positive_rate']:.4f} ({metrics['benign_false_positive_rate'] * 100:.2f}%)")
    print(f"Calibrated Threshold:       {metrics['calibrated_threshold']:.6f}")
    if "performance" in metrics:
        p = metrics["performance"]
        if "batch_mean_latency_ms" in p:
            print(f"Batch Mean Latency:         {p['batch_mean_latency_ms']:.4f} ms/flow")
            print(f"Batch Throughput:           {p['batch_throughput_flows_sec']:.1f} flows/sec")
        if "p50_latency_ms" in p:
            print(f"Single-Flow Mean Latency:   {p['single_flow_mean_latency_ms']:.4f} ms/flow")
            print(f"Single-Flow P50 Latency:    {p['p50_latency_ms']:.4f} ms/flow")
            print(f"Single-Flow P95 Latency:    {p['p95_latency_ms']:.4f} ms/flow")
            print(f"Single-Flow P99 Latency:    {p['p99_latency_ms']:.4f} ms/flow")
    print(f"{'-' * 70}")
    print(f"{'Class':<25} {'Anomaly Detection Rate (Recall)':<30}")
    print(f"{'-' * 70}")
    for cls_name, rec in metrics.get("per_class_detection_rate", {}).items():
        print(f"{cls_name:<25} {rec:<30.4f}")
    print(f"{'=' * 70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train SentinelAI RF on real CIC-IDS2017 with per-file chronological split."
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        required=True,
        help="Path to directory containing CIC-IDS2017 CSV files",
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
    )
    parser.add_argument(
        "--model-version",
        type=str,
        default="3.0.0",
        help="Model version (3.0.0 = real CIC-IDS2017 trained)",
    )
    parser.add_argument(
        "--train-fraction",
        type=float,
        default=0.80,
        help="Fraction of each CSV file used for training (remainder = test)",
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=400000,
        help="Max training samples after balanced subsampling (for memory)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
    )
    parser.add_argument(
        "--skip-rf",
        action="store_true",
        default=False,
        help="Skip Random Forest training (e.g. if RF already trained)",
    )
    parser.add_argument(
        "--skip-if",
        action="store_true",
        default=False,
        help="Skip Isolation Forest training",
    )
    parser.add_argument(
        "--if-contamination",
        type=float,
        default=0.015,
        help="Contamination rate / calibration percentile on benign training data",
    )
    parser.add_argument(
        "--max-benign-samples",
        type=int,
        default=300000,
        help="Max benign training samples for Isolation Forest fitting",
    )
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.exists():
        logger.error(f"Dataset directory not found: {dataset_dir}")
        sys.exit(1)

    adapter = CICDatasetAdapter()

    # -- 1. Discover files --
    csv_files = find_csv_files(dataset_dir)
    if not csv_files:
        logger.error(f"No CSV files found in {dataset_dir}")
        sys.exit(1)

    logger.info(f"Found {len(csv_files)} CSV files: {[f.name for f in csv_files]}")

    # -- 2. Load each file with per-file chronological split --
    all_X_train = []
    all_y_train = []
    all_X_test = []
    all_y_test = []

    for csv_file in csv_files:
        logger.info(f"Loading {csv_file.name}...")
        t0 = time.perf_counter()
        X_tr, y_tr, X_te, y_te = load_and_split_csv(
            csv_file, adapter, train_fraction=args.train_fraction
        )
        elapsed = time.perf_counter() - t0

        train_dist = dict(collections.Counter(y_tr))
        test_dist = dict(collections.Counter(y_te))
        logger.info(
            f"  -> {len(X_tr)} train + {len(X_te)} test in {elapsed:.1f}s | "
            f"Train: {train_dist} | Test: {test_dist}"
        )

        all_X_train.append(X_tr)
        all_y_train.append(y_tr)
        all_X_test.append(X_te)
        all_y_test.append(y_te)

    X_train_raw = np.concatenate(all_X_train, axis=0)
    y_train_raw = np.concatenate(all_y_train, axis=0)
    X_test_raw = np.concatenate(all_X_test, axis=0)
    y_test_raw = np.concatenate(all_y_test, axis=0)

    logger.info(f"Combined TRAIN: {len(X_train_raw)} samples | Classes: {dict(collections.Counter(y_train_raw))}")
    logger.info(f"Combined TEST:  {len(X_test_raw)} samples | Classes: {dict(collections.Counter(y_test_raw))}")

    # -- 3. Verify class overlap --
    train_classes = set(y_train_raw)
    test_classes = set(y_test_raw)
    overlap = train_classes & test_classes
    test_only = test_classes - train_classes
    train_only = train_classes - test_classes

    logger.info(f"Class overlap: {sorted(overlap)}")
    if test_only:
        logger.warning(f"Classes in TEST only (will be filtered): {test_only}")
        mask = np.isin(y_test_raw, list(train_classes))
        X_test_raw = X_test_raw[mask]
        y_test_raw = y_test_raw[mask]
        logger.info(f"After filtering: {len(X_test_raw)} test samples")
    if train_only:
        logger.warning(f"Classes in TRAIN only: {train_only}")

    # -- 4. Subsample training data for memory --
    X_train, y_train = subsample_balanced(
        X_train_raw, y_train_raw,
        max_total=args.max_train_samples,
        random_state=args.random_state,
    )
    logger.info(f"Training samples after subsampling: {len(X_train)}")
    logger.info(f"Subsampled class distribution: {dict(collections.Counter(y_train))}")

    # Use full test set (no subsampling)
    X_test, y_test = X_test_raw, y_test_raw

    # -- 5. Data quality checks --
    assert not np.isnan(X_train).any(), "NaN in training features"
    assert not np.isinf(X_train).any(), "Inf in training features"
    assert not np.isnan(X_test).any(), "NaN in test features"
    assert not np.isinf(X_test).any(), "Inf in test features"
    logger.info("Data quality check passed (no NaN/Inf)")

    # -- 6. Train --
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_rf:
        logger.info("=" * 60)
        logger.info("TRAINING RANDOM FOREST")
        logger.info("=" * 60)
        clf, training_info = train_random_forest(X_train, y_train, random_state=args.random_state)

        # -- 7. Evaluate on chronological test set --
        logger.info("=" * 60)
        logger.info("EVALUATING ON CHRONOLOGICAL TEST SET (last 20% of each file)")
        logger.info("=" * 60)
        metrics = evaluate_model(clf, X_test, y_test, feature_names=CANONICAL_ML_FEATURES)
        print_evaluation_summary(metrics, "CHRONOLOGICAL TEST (last 20% per file)")

        # -- 8. Train-set evaluation for leakage audit --
        train_metrics = evaluate_model(clf, X_train, y_train, feature_names=CANONICAL_ML_FEATURES)
        print_evaluation_summary(train_metrics, "TRAINING SET (LEAKAGE AUDIT)")

        train_acc = train_metrics["overall_accuracy"]
        test_acc = metrics["overall_accuracy"]
        gap = train_acc - test_acc
        logger.info(f"Train-Test accuracy gap: {gap:.4f} (train={train_acc:.4f}, test={test_acc:.4f})")
        if gap > 0.15:
            logger.warning(f"Large train-test gap ({gap:.4f}) may indicate overfitting!")

        # -- 9. Build and save artifacts --
        dataset_metadata = {
            "source_dataset": "CIC-IDS2017",
            "source_hash": compute_dir_hash(csv_files),
            "source_files": [f.name for f in csv_files],
            "split_strategy": f"attack-aware per-class chronological ({args.train_fraction:.0%} train / {1 - args.train_fraction:.0%} test within each CSV)",
            "total_train_raw": int(len(X_train_raw)),
            "total_train_subsampled": int(len(X_train)),
            "total_test": int(len(X_test)),
            "train_classes": sorted(set(y_train)),
            "test_classes": sorted(set(y_test)),
            "class_overlap": sorted(overlap),
            "random_state": args.random_state,
        }

        model, metadata = build_trained_model_artifacts(
            model=clf,
            metrics=metrics,
            dataset_metadata=dataset_metadata,
            model_name=args.model_name,
            model_version=args.model_version,
            feature_names=CANONICAL_ML_FEATURES,
        )

        model_file, meta_file = save_trained_artifacts(model, metadata, out_dir)
        logger.info(f"Model saved: {model_file}")
        logger.info(f"Metadata saved: {meta_file}")

    if not args.skip_if:
        logger.info("=" * 60)
        logger.info("TRAINING ISOLATION FOREST (UNSUPERVISED ANOMALY DETECTION)")
        logger.info("=" * 60)
        benign_indices = np.where(y_train_raw == "BENIGN")[0]
        if len(benign_indices) > args.max_benign_samples:
            rng = np.random.RandomState(args.random_state)
            benign_indices = rng.choice(benign_indices, size=args.max_benign_samples, replace=False)
        X_train_benign = X_train_raw[benign_indices]
        logger.info(f"Fitting Isolation Forest on {len(X_train_benign)} benign flows (out of {np.sum(y_train_raw == 'BENIGN')})...")

        if_clf, if_training_info = train_isolation_forest(
            X_train_benign,
            random_state=args.random_state,
            calibration_quantile=args.if_contamination,
        )

        logger.info("=" * 60)
        logger.info("EVALUATING ISOLATION FOREST ON CHRONOLOGICAL TEST SET")
        logger.info("=" * 60)
        if_metrics = evaluate_isolation_forest(
            if_clf,
            X_test,
            y_test,
            calibrated_threshold=if_training_info["calibrated_threshold"],
            feature_names=CANONICAL_ML_FEATURES,
        )
        print_if_evaluation_summary(if_metrics, "CHRONOLOGICAL TEST (ISOLATION FOREST)")

        if_dataset_metadata = {
            "source_dataset": "CIC-IDS2017",
            "source_hash": compute_dir_hash(csv_files),
            "source_files": [f.name for f in csv_files],
            "split_strategy": f"attack-aware per-class chronological ({args.train_fraction:.0%} train / {1 - args.train_fraction:.0%} test within each CSV)",
            "total_benign_train": int(len(X_train_benign)),
            "total_test": int(len(X_test)),
            "calibration_quantile": args.if_contamination,
            "calibrated_threshold": if_training_info["calibrated_threshold"],
            "random_state": args.random_state,
        }

        if_model, if_meta = build_if_model_artifacts(
            model=if_clf,
            metrics=if_metrics,
            dataset_metadata=if_dataset_metadata,
            model_name="sentinel_if_production",
            model_version=args.model_version,
            feature_names=CANONICAL_ML_FEATURES,
        )

        if_model_file, if_meta_file = save_if_artifacts(if_model, if_meta, out_dir)
        logger.info(f"Isolation Forest Model saved: {if_model_file}")
        logger.info(f"Isolation Forest Metadata saved: {if_meta_file}")

    # -- 10. Final summary --
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE SUMMARY")
    print("=" * 70)
    if not args.skip_rf:
        print(f"Model:           {args.model_name} v{args.model_version}")
        print(f"Algorithm:       RandomForestClassifier")
        print(f"Train samples:   {len(X_train)} (subsampled from {len(X_train_raw)})")
        print(f"Test samples:    {len(X_test)}")
        print(f"Split strategy:  Attack-aware per-class chronological ({args.train_fraction:.0%}/{1 - args.train_fraction:.0%})")
        print(f"Classes:         {sorted(set(y_train))}")
        print(f"Test Accuracy:   {metrics['overall_accuracy']:.4f}")
        print(f"Test Macro F1:   {metrics['macro_f1']:.4f}")
        print(f"Test Weighted F1:{metrics['weighted_f1']:.4f}")
        print(f"Benign FPR:      {metrics['benign_false_positive_rate']:.4f}")
        if "batch_mean_latency_ms" in metrics["performance"]:
            print(f"Batch Mean Latency:    {metrics['performance']['batch_mean_latency_ms']:.4f} ms/flow")
            print(f"Batch Throughput:      {metrics['performance']['batch_throughput_flows_sec']:.1f} flows/sec")
        if "p50_latency_ms" in metrics["performance"]:
            print(f"Single-Flow Mean Lat:  {metrics['performance']['single_flow_mean_latency_ms']:.4f} ms/flow")
            print(f"P50 Latency:           {metrics['performance']['p50_latency_ms']:.4f} ms/flow")
            print(f"P95 Latency:           {metrics['performance']['p95_latency_ms']:.4f} ms/flow")
            print(f"P99 Latency:           {metrics['performance']['p99_latency_ms']:.4f} ms/flow")
            print(f"Single-Flow Throughput:{metrics['performance']['single_flow_throughput_flows_sec']:.1f} flows/sec")
        print(f"Train-Test Gap:  {gap:.4f}")
        print(f"Saved to:        {model_file}")
    if not args.skip_if:
        print(f"\nModel:           sentinel_if_production v{args.model_version}")
        print(f"Algorithm:       IsolationForest")
        print(f"Benign Train:    {len(X_train_benign)}")
        print(f"Holdout Samples: {len(X_test)}")
        print(f"Anomaly F1:      {if_metrics['anomaly_f1']:.4f}")
        print(f"Anomaly Recall:  {if_metrics['anomaly_recall']:.4f}")
        print(f"Benign FPR:      {if_metrics['benign_false_positive_rate']:.4f}")
        print(f"Threshold:       {if_metrics['calibrated_threshold']:.6f}")
        print(f"Saved to:        {if_model_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()

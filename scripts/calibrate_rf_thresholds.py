"""Deterministic Validation-Only Threshold Calibration for SentinelAI Random Forest.

CRITICAL INVARIANTS:
1. Strict Validation-Only: Operates ONLY on the training split (first 80% of each CSV).
   The final 566,157-flow holdout test set is NEVER loaded, accessed, or touched.
2. Derives class-specific probability thresholds by optimizing the precision/recall trade-off
   (harmonic mean F1) on a deterministic 20% validation split of the training data.
3. Persists resulting calibrated thresholds and detailed provenance into sentinel_rf_production.json.
"""

import argparse
import collections
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

# Ensure packages are importable
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from sentinel_detection.ml.dataset_adapter import CICDatasetAdapter
from sentinel_detection.ml.model_metadata import MLModelMetadata
from scripts.train_real_data import find_csv_files, load_and_split_csv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.calibrate_rf_thresholds")


def calibrate_class_thresholds(
    y_true: np.ndarray,
    proba: np.ndarray,
    classes: List[str],
    min_threshold: float = 0.40,
    max_threshold: float = 0.99,
    steps: int = 60,
) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """Grid-search class probability thresholds maximizing F1 on validation split."""
    thresholds: Dict[str, float] = {}
    provenance_details: Dict[str, Any] = {}

    grid = np.linspace(min_threshold, max_threshold, steps)

    for c in classes:
        if c == "BENIGN":
            continue

        c_idx = classes.index(c)
        p_c = proba[:, c_idx]
        y_binary = (y_true == c)
        n_pos = int(np.sum(y_binary))

        if n_pos == 0:
            thresholds[c] = 0.50
            provenance_details[c] = {"threshold": 0.50, "note": "No positive validation samples"}
            continue

        best_t = 0.50
        best_f1 = 0.0
        best_prec = 0.0
        best_rec = 0.0

        for t in grid:
            pred_bin = (p_c >= t)
            tp = int(np.sum(pred_bin & y_binary))
            fp = int(np.sum(pred_bin & ~y_binary))
            fn = int(np.sum(~pred_bin & y_binary))

            prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

            # Optimize for precision/recall balance
            if f1 > best_f1:
                best_f1 = f1
                best_t = t
                best_prec = prec
                best_rec = rec

        thresholds[c] = round(float(best_t), 4)
        provenance_details[c] = {
            "threshold": round(float(best_t), 4),
            "validation_support": n_pos,
            "validation_precision": round(best_prec, 4),
            "validation_recall": round(best_rec, 4),
            "validation_f1": round(best_f1, 4),
        }
        logger.info(
            f"Class {c:<22}: calibrated threshold = {best_t:.4f} "
            f"(Val Prec = {best_prec:.4f}, Val Rec = {best_rec:.4f}, Val F1 = {best_f1:.4f})"
        )

    return thresholds, provenance_details


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate Random Forest class probability thresholds on validation split ONLY."
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=r"D:\DATASET\MachineLearningCSV\MachineLearningCVE",
        help="Path to directory containing CIC-IDS2017 CSV files",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="packages/detection/sentinel_detection/ml/models",
        help="Directory containing trained model artifacts",
    )
    parser.add_argument(
        "--val-fraction",
        type=float,
        default=0.20,
        help="Fraction of training split reserved for validation calibration",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
    )
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    rf_model_path = models_dir / "sentinel_rf_production.joblib"
    rf_meta_path = models_dir / "sentinel_rf_production.json"

    if not rf_model_path.exists() or not rf_meta_path.exists():
        logger.error(f"Model artifacts missing at {models_dir}")
        sys.exit(1)

    logger.info(f"Loading Random Forest model from {rf_model_path}...")
    rf = joblib.load(rf_model_path)
    with open(rf_meta_path, "r", encoding="utf-8") as f:
        metadata_dict = json.load(f)

    # 1. Load ONLY training split (train_fraction=0.80). Holdout test split is DISCARDED immediately.
    dataset_dir = Path(args.dataset_dir)
    csv_files = find_csv_files(dataset_dir)
    adapter = CICDatasetAdapter()

    all_X_train = []
    all_y_train = []

    logger.info("Loading training split (first 80% per CSV) for validation calibration...")
    for csv_file in csv_files:
        t0 = time.perf_counter()
        X_tr, y_tr, _, _ = load_and_split_csv(csv_file, adapter, train_fraction=0.80)
        elapsed = time.perf_counter() - t0
        logger.info(f"  {csv_file.name}: {len(X_tr)} train flows in {elapsed:.1f}s")
        all_X_train.append(X_tr)
        all_y_train.append(y_tr)

    X_train_raw = np.concatenate(all_X_train, axis=0)
    y_train_raw = np.concatenate(all_y_train, axis=0)
    logger.info(f"Total training split samples: {len(X_train_raw)}")

    # 2. Partition training split into 80% fit / 20% validation-calibration
    rng = np.random.RandomState(args.random_state)
    val_indices = []
    for c in np.unique(y_train_raw):
        c_idx = np.where(y_train_raw == c)[0]
        n_val = max(1, int(len(c_idx) * args.val_fraction))
        chosen = rng.choice(c_idx, size=n_val, replace=False)
        val_indices.extend(chosen)

    val_indices = np.array(val_indices)
    X_val = X_train_raw[val_indices]
    y_val = y_train_raw[val_indices]

    val_dist = dict(collections.Counter(y_val))
    logger.info(f"Validation Calibration Set: {len(X_val)} samples | Distribution: {val_dist}")

    # 3. Compute predicted probabilities on validation set
    logger.info("Predicting probabilities on validation set...")
    t0 = time.perf_counter()
    proba_val = rf.predict_proba(X_val)
    logger.info(f"Probabilities computed in {time.perf_counter() - t0:.2f}s")

    classes = list(rf.classes_)

    # 4. Calibrate thresholds
    thresholds, provenance_details = calibrate_class_thresholds(
        y_val, proba_val, classes
    )

    # 5. Measure validation FPR reduction
    benign_mask = (y_val == "BENIGN")
    raw_preds = rf.predict(X_val)
    raw_val_fpr = float(np.sum(raw_preds[benign_mask] != "BENIGN") / np.sum(benign_mask))

    calib_preds = np.full(len(X_val), "BENIGN", dtype=object)
    rf_best_idx = np.argmax(proba_val, axis=1)
    rf_best_class = np.array([classes[i] for i in rf_best_idx])
    rf_best_prob = np.max(proba_val, axis=1)

    for i in range(len(X_val)):
        c = rf_best_class[i]
        p = rf_best_prob[i]
        if c != "BENIGN" and p >= thresholds.get(c, 0.50):
            calib_preds[i] = c

    calib_val_fpr = float(np.sum(calib_preds[benign_mask] != "BENIGN") / np.sum(benign_mask))
    logger.info(f"Validation Benign FPR: raw={raw_val_fpr:.4f} -> calibrated={calib_val_fpr:.4f}")

    # 6. Save updated metadata with calibration provenance
    calibration_provenance = {
        "calibrated_at": datetime.now(timezone.utc).isoformat(),
        "methodology": "Deterministic grid-search maximizing F1 score on a 20% validation split of the training set with zero holdout exposure",
        "validation_samples_count": len(X_val),
        "validation_class_distribution": val_dist,
        "validation_raw_benign_fpr": round(raw_val_fpr, 4),
        "validation_calibrated_benign_fpr": round(calib_val_fpr, 4),
        "class_calibration_details": provenance_details,
    }

    metadata_dict["class_thresholds"] = thresholds
    metadata_dict["calibration_provenance"] = calibration_provenance

    # Validate against MLModelMetadata schema
    validated_meta = MLModelMetadata.model_validate(metadata_dict)

    with open(rf_meta_path, "w", encoding="utf-8") as f:
        f.write(validated_meta.model_dump_json(indent=2))

    logger.info(f"Successfully updated RF model metadata at {rf_meta_path}")
    print("\n" + "=" * 70)
    print("CALIBRATED RANDOM FOREST CLASS THRESHOLDS (VALIDATION ONLY)")
    print("=" * 70)
    for c, t in sorted(thresholds.items()):
        details = provenance_details.get(c, {})
        print(f"  {c:<22}: {t:.4f} (Val F1: {details.get('validation_f1', 0.0):.4f}, Support: {details.get('validation_support', 0)})")
    print(f"\nValidation Benign FPR: {raw_val_fpr:.2%} -> {calib_val_fpr:.2%} (Reduced by {(raw_val_fpr - calib_val_fpr)/raw_val_fpr * 100:.1f}%)")
    print(f"Metadata saved to: {rf_meta_path}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

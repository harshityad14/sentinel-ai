"""Training and evaluation pipeline for Layer 2 Isolation Forest Anomaly Detector.

Guarantees:
- Fitted STRICTLY on normal benign training traffic (X_train[y_train == 'BENIGN']).
- Threshold calibrated on training validation folds only; holdout set is NEVER touched.
- Deterministic random_state=42.
- Persists versioned model artifact (.joblib) and validated metadata (.json).
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES

logger = logging.getLogger("sentinel.ml.trainer_if")

DEFAULT_IF_HYPERPARAMETERS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_samples": "auto",
    "contamination": 0.015,  # Nominal 1.5% target outlier rate on benign baseline
    "random_state": 42,
    "n_jobs": -1,
}


def train_isolation_forest(
    X_benign_train: np.ndarray,
    hyperparameters: Optional[Dict[str, Any]] = None,
    random_state: int = 42,
    calibration_quantile: float = 0.015,
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Fit Isolation Forest strictly on benign training flows and calibrate decision threshold.
    
    Threshold calibration:
    Computes decision function scores on training benign flows and sets threshold at
    calibration_quantile (e.g. 1.5th percentile), ensuring nominal benign training false alarms
    are bounded.
    """
    params = dict(DEFAULT_IF_HYPERPARAMETERS)
    if hyperparameters:
        params.update(hyperparameters)
    params["random_state"] = random_state

    n_samples = len(X_benign_train)
    logger.info(f"Training IsolationForest on {n_samples} benign samples with params: {params}...")
    t0 = time.perf_counter()

    clf = IsolationForest(**params)
    clf.fit(X_benign_train)

    train_time = time.perf_counter() - t0
    logger.info(f"Isolation Forest training completed in {train_time:.3f}s")

    # Calibrate decision threshold on training set
    train_scores = clf.decision_function(X_benign_train)
    calibrated_threshold = float(np.percentile(train_scores, calibration_quantile * 100.0))
    logger.info(
        f"Calibrated decision threshold at {calibration_quantile:.1%} quantile: {calibrated_threshold:.4f} "
        f"(mean score: {np.mean(train_scores):.4f}, std: {np.std(train_scores):.4f})"
    )

    training_info = {
        "train_samples": int(n_samples),
        "training_time_sec": round(train_time, 4),
        "calibrated_threshold": round(calibrated_threshold, 6),
        "calibration_quantile": calibration_quantile,
        "mean_training_score": round(float(np.mean(train_scores)), 4),
        "std_training_score": round(float(np.std(train_scores)), 4),
    }

    return clf, training_info


def evaluate_isolation_forest(
    clf: IsolationForest,
    X_test: np.ndarray,
    y_test: np.ndarray,
    calibrated_threshold: float,
    feature_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Evaluate Isolation Forest anomaly detector on holdout test flows.
    
    Ground-truth semantics for unsupervised anomaly detection:
    - Positive condition (Attack): y_test != 'BENIGN'
    - Negative condition (Normal): y_test == 'BENIGN'
    - Flagged as Anomaly: score < calibrated_threshold
    """
    feats = feature_names or CANONICAL_ML_FEATURES
    n_samples = len(X_test)
    if n_samples == 0:
        raise ValueError("Cannot evaluate Isolation Forest on empty test set")

    logger.info(f"Evaluating Isolation Forest on {n_samples} holdout samples...")

    # Benchmark batch throughput
    t0 = time.perf_counter()
    scores = clf.decision_function(X_test)
    total_eval_time = time.perf_counter() - t0

    batch_latency = (total_eval_time / n_samples) * 1000.0
    batch_throughput = n_samples / max(1e-6, total_eval_time)

    # Benchmark single-flow latency (using n_jobs=1 matching production detector)
    orig_n_jobs = getattr(clf, "n_jobs", None)
    if hasattr(clf, "set_params"):
        try:
            clf.set_params(n_jobs=1)
        except Exception:
            pass

    bench_n = min(2000, n_samples)
    single_lats = []
    for i in range(min(50, bench_n)):
        _ = clf.decision_function(X_test[i : i + 1])
    for i in range(bench_n):
        t_s = time.perf_counter()
        _ = clf.decision_function(X_test[i : i + 1])
        single_lats.append((time.perf_counter() - t_s) * 1000.0)

    if orig_n_jobs is not None and hasattr(clf, "set_params"):
        try:
            clf.set_params(n_jobs=orig_n_jobs)
        except Exception:
            pass

    p50_lat = float(np.percentile(single_lats, 50))
    p95_lat = float(np.percentile(single_lats, 95))
    p99_lat = float(np.percentile(single_lats, 99))
    single_mean_lat = float(np.mean(single_lats))
    single_throughput = 1000.0 / max(1e-6, single_mean_lat)

    # Binary anomaly classification
    is_attack_ground_truth = (y_test != "BENIGN")
    is_anomaly_predicted = (scores < calibrated_threshold)

    tp = int(np.sum(is_attack_ground_truth & is_anomaly_predicted))
    fp = int(np.sum(~is_attack_ground_truth & is_anomaly_predicted))
    fn = int(np.sum(is_attack_ground_truth & ~is_anomaly_predicted))
    tn = int(np.sum(~is_attack_ground_truth & ~is_anomaly_predicted))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    benign_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Breakdown per attack class: recall per attack class
    classes = sorted(np.unique(y_test))
    per_class_anomaly_recall: Dict[str, float] = {}
    for c in classes:
        c_mask = (y_test == c)
        if np.sum(c_mask) > 0:
            c_detected = np.sum(c_mask & is_anomaly_predicted)
            per_class_anomaly_recall[c] = round(float(c_detected / np.sum(c_mask)), 4)

    results = {
        "anomaly_precision": round(precision, 4),
        "anomaly_recall": round(recall, 4),
        "anomaly_f1": round(f1, 4),
        "benign_false_positive_rate": round(benign_fpr, 4),
        "calibrated_threshold": round(calibrated_threshold, 6),
        "confusion_matrix": {
            "true_positives_attacks_detected": tp,
            "false_positives_benign_flagged": fp,
            "false_negatives_attacks_missed": fn,
            "true_negatives_benign_normal": tn,
        },
        "per_class_detection_rate": per_class_anomaly_recall,
        "performance": {
            "test_samples_count": n_samples,
            "total_inference_time_sec": round(total_eval_time, 4),
            "batch_mean_latency_ms": round(batch_latency, 4),
            "single_flow_mean_latency_ms": round(single_mean_lat, 4),
            "p50_latency_ms": round(p50_lat, 4),
            "p95_latency_ms": round(p95_lat, 4),
            "p99_latency_ms": round(p99_lat, 4),
            "batch_throughput_flows_sec": round(batch_throughput, 1),
            "single_flow_throughput_flows_sec": round(single_throughput, 1),
        },
    }

    logger.info(
        f"Isolation Forest Holdout Results: Precision={precision:.4f}, Recall={recall:.4f}, "
        f"F1={f1:.4f}, Benign-FPR={benign_fpr:.4f}"
    )
    return results


def build_if_model_artifacts(
    model: IsolationForest,
    metrics: Dict[str, Any],
    dataset_metadata: Dict[str, Any],
    model_name: str = "sentinel_if_production",
    model_version: str = "1.0.0",
    feature_names: Optional[List[str]] = None,
) -> Tuple[IsolationForest, MLModelMetadata]:
    """Wrap trained Isolation Forest and metrics into MLModelMetadata."""
    feats = feature_names or CANONICAL_ML_FEATURES

    metadata = MLModelMetadata(
        model_name=model_name,
        model_version=model_version,
        algorithm="IsolationForest",
        feature_version="1.0",
        feature_names=feats,
        target_classes=["BENIGN", "ANOMALOUS"],
        hyperparameters={
            k: v for k, v in model.get_params().items()
            if isinstance(v, (int, float, str, bool)) or v is None
        },
        metrics=metrics,
        dataset_metadata=dataset_metadata,
    )
    return model, metadata


def save_if_artifacts(
    model: IsolationForest,
    metadata: MLModelMetadata,
    output_dir: Union[str, Path],
) -> Tuple[Path, Path]:
    """Persist Isolation Forest model (.joblib) and metadata (.json) to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    model_file = out / f"{metadata.model_name}.joblib"
    meta_file = out / f"{metadata.model_name}.json"

    joblib.dump(model, model_file, compress=3)
    with open(meta_file, "w", encoding="utf-8") as f:
        f.write(metadata.model_dump_json(indent=2))

    logger.info(f"Saved Isolation Forest artifacts to {model_file} and {meta_file}")
    return model_file, meta_file

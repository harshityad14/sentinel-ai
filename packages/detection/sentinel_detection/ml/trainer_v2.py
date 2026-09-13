"""Production Random Forest training and evaluation pipeline for SentinelAI.

Enforces:
- Reproducible training with deterministic seed=42
- Balanced class weights (class_weight='balanced_subsample')
- Exhaustive evaluation (macro/weighted F1, precision, recall, FPR, confusion matrix)
- Real measured latency and throughput benchmarks
- Zero hardcoded or estimated metrics
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES

logger = logging.getLogger("sentinel.ml.trainer_v2")

DEFAULT_RF_HYPERPARAMETERS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 16,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": 42,
    "n_jobs": -1,
}


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    hyperparameters: Optional[Dict[str, Any]] = None,
    random_state: int = 42,
) -> Tuple[RandomForestClassifier, Dict[str, Any]]:
    """Train Random Forest classifier with deterministic hyperparameters."""
    params = dict(DEFAULT_RF_HYPERPARAMETERS)
    if hyperparameters:
        params.update(hyperparameters)
    params["random_state"] = random_state

    logger.info(f"Training RandomForestClassifier on {X_train.shape[0]} samples with params: {params}...")
    t0 = time.perf_counter()

    clf = RandomForestClassifier(**params)
    clf.fit(X_train, y_train)

    train_time = time.perf_counter() - t0
    logger.info(f"Training completed in {train_time:.3f}s. Classes: {clf.classes_.tolist()}")

    training_info = {
        "train_samples": int(X_train.shape[0]),
        "training_time_sec": round(train_time, 4),
        "classes": clf.classes_.tolist(),
        "hyperparameters": {k: v for k, v in params.items() if k != "n_jobs"},
    }
    return clf, training_info


def evaluate_model(
    clf: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Perform rigorous evaluation against a test split, measuring precision, recall, F1, FPR, and latency.
    
    All metrics are computed strictly from real predictions on X_test.
    """
    feats = feature_names or CANONICAL_ML_FEATURES
    n_samples = len(X_test)
    if n_samples == 0:
        raise ValueError("Cannot evaluate model on empty test set")

    logger.info(f"Evaluating model on {n_samples} test samples...")

    # Benchmark single-threaded inference latency and throughput
    t0 = time.perf_counter()
    y_pred = clf.predict(X_test)
    total_eval_time = time.perf_counter() - t0

    latency_ms_per_flow = (total_eval_time / n_samples) * 1000.0
    throughput_flows_sec = n_samples / max(1e-6, total_eval_time)

    # Benchmark single-flow latency distribution (matching production detector n_jobs=1)
    orig_n_jobs = getattr(clf, "n_jobs", None)
    if hasattr(clf, "set_params"):
        try:
            clf.set_params(n_jobs=1)
        except Exception:
            pass

    bench_n = min(2000, n_samples)
    single_latencies = []
    for i in range(min(50, bench_n)):
        _ = clf.predict(X_test[i : i + 1])
    for i in range(bench_n):
        t_s = time.perf_counter()
        _ = clf.predict(X_test[i : i + 1])
        single_latencies.append((time.perf_counter() - t_s) * 1000.0)

    if orig_n_jobs is not None and hasattr(clf, "set_params"):
        try:
            clf.set_params(n_jobs=orig_n_jobs)
        except Exception:
            pass

    p50_latency = float(np.percentile(single_latencies, 50))
    p95_latency = float(np.percentile(single_latencies, 95))
    p99_latency = float(np.percentile(single_latencies, 99))
    single_mean_latency = float(np.mean(single_latencies))
    single_throughput = 1000.0 / max(1e-6, single_mean_latency)

    classes = clf.classes_.tolist()
    cm = confusion_matrix(y_test, y_pred, labels=classes)

    overall_acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    macro_prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))

    # Per-class metrics and False Positive Rates
    per_class_metrics: Dict[str, Dict[str, float]] = {}
    benign_fpr = 0.0

    for idx, class_name in enumerate(classes):
        # TP, FP, FN, TN calculation from confusion matrix
        tp = int(cm[idx, idx])
        fn = int(np.sum(cm[idx, :]) - tp)
        fp = int(np.sum(cm[:, idx]) - tp)
        tn = int(np.sum(cm) - (tp + fn + fp))

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        per_class_metrics[class_name] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "support": int(np.sum(cm[idx, :])),
        }

        # If this is the benign class, record benign false positive rate
        # (i.e. benign traffic misclassified as threat)
        if class_name.upper() in ("BENIGN", "NORMAL"):
            # For benign, FP = benign traffic predicted as an attack
            # Here: benign instances are class_name row.
            # Number of benign instances classified as non-benign is fn for benign class:
            benign_total = int(np.sum(cm[idx, :]))
            benign_misclassified = benign_total - tp
            benign_fpr = float(benign_misclassified / benign_total) if benign_total > 0 else 0.0

    # Top feature importances
    feature_importances: Dict[str, float] = {}
    if hasattr(clf, "feature_importances_"):
        for f_name, imp in sorted(zip(feats, clf.feature_importances_), key=lambda x: x[1], reverse=True):
            feature_importances[f_name] = round(float(imp), 4)

    results: Dict[str, Any] = {
        "overall_accuracy": round(overall_acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "benign_false_positive_rate": round(benign_fpr, 4),
        "classes": classes,
        "confusion_matrix": cm.tolist(),
        "per_class": per_class_metrics,
        "feature_importances": feature_importances,
        "performance": {
            "test_samples_count": n_samples,
            "total_inference_time_sec": round(total_eval_time, 4),
            "batch_mean_latency_ms": round(latency_ms_per_flow, 4),
            "mean_latency_ms": round(latency_ms_per_flow, 4),
            "single_flow_mean_latency_ms": round(single_mean_latency, 4),
            "p50_latency_ms": round(p50_latency, 4),
            "p95_latency_ms": round(p95_latency, 4),
            "p99_latency_ms": round(p99_latency, 4),
            "batch_throughput_flows_sec": round(throughput_flows_sec, 1),
            "single_flow_throughput_flows_sec": round(single_throughput, 1),
            "throughput_flows_sec": round(throughput_flows_sec, 1),
        },
    }

    logger.info(
        f"Evaluation results: Accuracy={overall_acc:.4f}, Macro-F1={macro_f1:.4f}, "
        f"Benign-FPR={benign_fpr:.4f}, Latency={latency_ms_per_flow:.3f}ms/flow"
    )
    return results


def build_trained_model_artifacts(
    model: RandomForestClassifier,
    metrics: Dict[str, Any],
    dataset_metadata: Dict[str, Any],
    model_name: str = "sentinel_rf_production",
    model_version: str = "2.0.0",
    feature_names: Optional[List[str]] = None,
) -> Tuple[RandomForestClassifier, MLModelMetadata]:
    """Wrap trained model and actual measured metrics into validated MLModelMetadata."""
    feats = feature_names or CANONICAL_ML_FEATURES

    metadata = MLModelMetadata(
        model_name=model_name,
        model_version=model_version,
        algorithm="RandomForestClassifier",
        feature_version="1.0",
        feature_names=feats,
        target_classes=model.classes_.tolist(),
        hyperparameters={
            k: v for k, v in model.get_params().items()
            if isinstance(v, (int, float, str, bool)) or v is None
        },
        metrics=metrics,
        dataset_metadata=dataset_metadata,
    )
    return model, metadata


def save_trained_artifacts(
    model: RandomForestClassifier,
    metadata: MLModelMetadata,
    output_dir: Union[str, Path],
) -> Tuple[Path, Path]:
    """Persist trained model (.joblib) and metadata (.json) to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    model_file = out / f"{metadata.model_name}.joblib"
    meta_file = out / f"{metadata.model_name}.json"

    joblib.dump(model, model_file, compress=3)
    with open(meta_file, "w", encoding="utf-8") as f:
        f.write(metadata.model_dump_json(indent=2))

    logger.info(f"Saved model artifacts to {model_file} and {meta_file}")
    return model_file, meta_file

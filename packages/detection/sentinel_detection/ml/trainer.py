"""Model training code for supervised threat classifiers.

Separated from inference runtime to ensure clean decoupling.
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple
import joblib
from sklearn.ensemble import RandomForestClassifier

from sentinel_detection.ml.model_metadata import MLModelMetadata


# Standard canonical numerical feature columns derived from FeatureVector.to_flat_dict()
CANONICAL_ML_FEATURES: List[str] = [
    "net_duration_sec",
    "net_total_bytes",
    "net_forward_bytes",
    "net_backward_bytes",
    "net_total_packets",
    "net_forward_packets",
    "net_backward_packets",
    "net_bytes_per_second",
    "net_packets_per_second",
    "net_byte_asymmetry_ratio",
    "net_mean_packet_size",
    "net_packet_size_std",
    "time_mean_inter_arrival_sec",
    "time_inter_arrival_std_sec",
    "time_jitter_ratio",
]

DEFAULT_TARGET_CLASSES: List[str] = [
    "BENIGN",
    "SYN_FLOOD",
    "UDP_FLOOD",
    "PORT_SCAN",
    "DATA_EXFILTRATION",
]


def create_deterministic_baseline_model(
    feature_names: Optional[List[str]] = None,
    target_classes: Optional[List[str]] = None,
) -> Tuple[RandomForestClassifier, MLModelMetadata]:
    """Build a deterministic baseline Random Forest fixture model for testing inference pipeline.
    
    Generates synthetic deterministic training samples to initialize the classifier
    structure without external network access or fake production claims.
    """
    features = feature_names or CANONICAL_ML_FEATURES
    classes = target_classes or DEFAULT_TARGET_CLASSES

    # Deterministic dataset for fixture initialization across all canonical profiles
    X: List[List[float]] = []
    y: List[str] = []

    # 1. BENIGN: Short web requests (duration 0.5-3.0s, 6-20 pkts, balanced bytes)
    for i in range(12):
        X.append([0.5 + i * 0.2, 800.0 + i * 300, 400.0 + i * 150, 400.0 + i * 150, 6 + i, 3, 3 + i, 500.0, 5.0, 0.5, 120.0, 20.0, 0.1, 0.05, 0.3])
        y.append("BENIGN")

    # BENIGN: Medium/Long connections (duration 10-30s, 30-100 pkts, balanced)
    for i in range(12):
        X.append([10.0 + i * 2, 5000.0 + i * 1000, 2500.0 + i * 500, 2500.0 + i * 500, 30 + i * 2, 15 + i, 15 + i, 250.0, 2.0, 0.5, 166.0, 40.0, 0.3, 0.05, 0.2])
        y.append("BENIGN")

    # 2. SYN_FLOOD samples (high packet rate, small packets, high PPS, zero inbound)
    for i in range(12):
        X.append([5.0, 3000.0, 3000.0, 0.0, 50 + i * 10, 50 + i * 10, 0, 600.0, 100.0 + i * 10, 1.0, 60.0, 2.0, 0.01, 0.002, 0.2])
        y.append("SYN_FLOOD")

    # 3. UDP_FLOOD samples (high byte rate, high PPS, high volume)
    for i in range(12):
        X.append([3.0, 50000.0 + i * 5000, 50000.0, 0.0, 100 + i * 10, 100, 0, 16000.0, 35.0, 1.0, 500.0, 10.0, 0.03, 0.005, 0.16])
        y.append("UDP_FLOOD")

    # 4. PORT_SCAN samples (instant probe <= 0.05s, 1-2 packets per flow, 0 inbound)
    for i in range(12):
        X.append([0.02, 120.0, 120.0, 0.0, 2, 2, 0, 6000.0, 100.0, 1.0, 60.0, 0.0, 0.01, 0.001, 0.05])
        y.append("PORT_SCAN")

    # 5. DATA_EXFILTRATION samples (very high outbound bytes, extreme byte asymmetry)
    for i in range(12):
        X.append([60.0, 25000000.0, 24900000.0, 100000.0, 20000, 19500, 500, 416666.0, 333.0, 0.996, 1250.0, 200.0, 0.003, 0.001, 0.33])
        y.append("DATA_EXFILTRATION")

    clf = RandomForestClassifier(
        n_estimators=25,
        max_depth=6,
        random_state=42,
        min_samples_split=2,
    )
    clf.fit(X, y)

    metadata = MLModelMetadata(
        model_name="sentinel_rf_baseline",
        model_version="1.0.0-baseline",
        algorithm="RandomForestClassifier",
        feature_version="1.0",
        feature_names=features,
        target_classes=clf.classes_.tolist(),
        hyperparameters={"n_estimators": 25, "max_depth": 6, "random_state": 42},
        metrics={
            "status": "IMPLEMENTED_INFERENCE_INFRASTRUCTURE",
            "evaluation_note": "Deterministic fixture baseline for validating inference architecture; production models will be trained on full historical PCAP datasets.",
        },
    )

    return clf, metadata


def save_model_artifacts(
    model: RandomForestClassifier,
    metadata: MLModelMetadata,
    output_dir: Path,
) -> Path:
    """Save model binary (.joblib) and metadata (.json) to target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / f"{metadata.model_name}.joblib"
    meta_path = output_dir / f"{metadata.model_name}.json"

    joblib.dump(model, model_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        f.write(metadata.model_dump_json(indent=2))

    return model_path

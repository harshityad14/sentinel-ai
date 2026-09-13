"""Production unsupervised anomaly detector using Isolation Forest for SentinelAI.

Layer 2 in the 3-layer threat detection architecture:
- Trained strictly on benign network traffic.
- Operates on the authoritative 15 CANONICAL_ML_FEATURES.
- Identifies unusual, out-of-distribution network traffic without requiring attack labels.
- Emits DetectionSignal with DetectorType.STATISTICAL and ThreatType.BEHAVIORAL_ANOMALY.
- Features clean deterministic fallback baseline for CI and clean environments.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel_detection.base import BaseDetector
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector

logger = logging.getLogger("sentinel.ml.isolation_forest")


def create_deterministic_if_baseline(
    feature_names: Optional[List[str]] = None,
) -> Tuple[IsolationForest, MLModelMetadata]:
    """Create a deterministic baseline Isolation Forest model fixture for testing and fallback."""
    feats = feature_names or CANONICAL_ML_FEATURES

    # Deterministic benign profile samples (matching trainer.py canonical profiles)
    X_benign: List[List[float]] = []
    # Short web requests (duration 0.5-3.0s, 6-20 pkts, balanced bytes)
    for i in range(25):
        X_benign.append([
            0.5 + i * 0.2, 800.0 + i * 300, 400.0 + i * 150, 400.0 + i * 150,
            6.0 + i, 3.0, 3.0 + i, 500.0, 5.0, 0.5, 120.0, 20.0, 0.1, 0.05, 0.3
        ])
    # Medium/long connections (duration 10-30s, 30-100 pkts, balanced)
    for i in range(25):
        X_benign.append([
            10.0 + i * 2, 5000.0 + i * 1000, 2500.0 + i * 500, 2500.0 + i * 500,
            30.0 + i * 2, 15.0 + i, 15.0 + i, 250.0, 2.0, 0.5, 166.0, 40.0, 0.3, 0.05, 0.2
        ])
    # Typical dummy flow profile (1s, 1000B, 10 pkts)
    for i in range(25):
        X_benign.append([
            1.0, 1000.0, 500.0, 500.0, 10.0, 5.0, 5.0, 1000.0, 10.0, 0.5, 100.0, 15.0, 0.1, 0.02, 0.2
        ])

    X_array = np.array(X_benign, dtype=np.float64)
    model = IsolationForest(
        n_estimators=50,
        contamination=0.01,
        random_state=42,
        n_jobs=1,
    )
    model.fit(X_array)

    train_scores = model.decision_function(X_array)
    calibrated_threshold = float(np.percentile(train_scores, 1.0))

    metadata = MLModelMetadata(
        model_name="sentinel_if_baseline",
        model_version="0.0.0-fallback",
        algorithm="IsolationForest",
        feature_version="1.0",
        feature_names=feats,
        target_classes=["BENIGN", "ANOMALOUS"],
        hyperparameters={
            "n_estimators": 50,
            "contamination": 0.01,
            "random_state": 42,
            "calibrated_threshold": calibrated_threshold,
        },
        metrics={
            "calibrated_threshold": calibrated_threshold,
            "nominal_benign_fpr": 0.01,
        },
        dataset_metadata={"source": "synthetic_deterministic_baseline"},
    )
    return model, metadata


class IsolationForestAnomalyDetector(BaseDetector):
    """Unsupervised anomaly detector identifying out-of-distribution traffic."""

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        model: Optional[IsolationForest] = None,
        metadata: Optional[MLModelMetadata] = None,
        min_confidence: float = 0.50,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_confidence=min_confidence,
            model_path=str(model_path) if model_path else None,
        )
        self.min_confidence = min_confidence

        if model is not None and metadata is not None:
            self.model = model
            self.metadata = metadata
        elif model_path is not None and metadata_path is not None:
            self.model, self.metadata = self._load_model_artifacts(model_path, metadata_path)
        else:
            models_dir = Path(__file__).resolve().parent / "models"
            pkg_model = models_dir / "sentinel_if_production.joblib"
            pkg_meta = models_dir / "sentinel_if_production.json"
            if pkg_model.exists() and pkg_meta.exists():
                logger.info(f"Loading packaged production Isolation Forest from {pkg_model}")
                self.model, self.metadata = self._load_model_artifacts(pkg_model, pkg_meta)
            else:
                logger.info("No production Isolation Forest weights found; loading deterministic fallback baseline")
                self.model, self.metadata = create_deterministic_if_baseline()

        # Extract calibrated decision threshold
        self.threshold = float(
            self.metadata.metrics.get("calibrated_threshold")
            or self.metadata.hyperparameters.get("calibrated_threshold", 0.0)
        )

    def _load_model_artifacts(
        self,
        model_path: Union[str, Path],
        metadata_path: Union[str, Path],
    ) -> Tuple[IsolationForest, MLModelMetadata]:
        m_path = Path(model_path)
        meta_path = Path(metadata_path)

        if not m_path.exists():
            raise FileNotFoundError(f"Isolation Forest model file not found: {m_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Isolation Forest metadata file not found: {meta_path}")

        model = joblib.load(m_path)
        if hasattr(model, "set_params"):
            try:
                model.set_params(n_jobs=1)
            except Exception:
                pass

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = MLModelMetadata.model_validate_json(f.read())

        return model, metadata

    @property
    def detector_name(self) -> str:
        return f"anomaly_{self.metadata.model_name}"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.STATISTICAL

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.BEHAVIORAL_ANOMALY

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or self.model is None:
            return None

        flat_features = features.to_flat_dict()
        feature_vector: List[float] = []
        imputed_features: List[str] = []

        for feat_name in self.metadata.feature_names:
            val = flat_features.get(feat_name)
            if val is None or not isinstance(val, (int, float)) or np.isnan(val) or np.isinf(val):
                feature_vector.append(0.0)
                imputed_features.append(feat_name)
            else:
                feature_vector.append(float(val))

        X = np.array([feature_vector], dtype=np.float64)

        # In scikit-learn IsolationForest:
        # decision_function score: negative indicates anomaly; positive indicates normal inlier.
        score = float(self.model.decision_function(X)[0])

        # Anomaly condition: score below calibrated threshold
        if score >= self.threshold:
            return None

        # Distance below threshold mapped smoothly to confidence [0.50, 0.99]
        # Larger negative distance from threshold = higher anomaly confidence
        distance = self.threshold - score
        confidence = min(0.99, max(0.50, 0.50 + (distance * 2.5)))

        if confidence < self.min_confidence:
            return None

        # Severity scales with anomaly extremity
        if confidence >= 0.85:
            severity = DetectionSeverity.HIGH
        elif confidence >= 0.70:
            severity = DetectionSeverity.MEDIUM
        else:
            severity = DetectionSeverity.LOW

        evidence = [
            DetectionEvidence(
                feature_name="isolation_forest_score",
                observed_value=round(score, 4),
                threshold_value=round(self.threshold, 4),
                description=(
                    f"Flow decision function score ({score:.4f}) fell below "
                    f"calibrated normal baseline threshold ({self.threshold:.4f})"
                ),
            )
        ]

        return DetectionSignal(
            signal_id=self._generate_signal_id(),
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            detector_type=DetectorType.STATISTICAL,
            detector_name=self.detector_name,
            confidence=round(confidence, 3),
            severity=severity,
            evidence=evidence,
            description=(
                f"Isolation Forest ({self.metadata.model_name} v{self.metadata.model_version}) "
                f"detected an out-of-distribution anomaly (score={score:.4f}, confidence={confidence:.1%})"
            ),
            metadata={
                "model_name": self.metadata.model_name,
                "model_version": self.metadata.model_version,
                "anomaly_score": round(score, 4),
                "threshold": round(self.threshold, 4),
                "imputed_features": imputed_features,
            },
        )

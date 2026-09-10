"""Supervised machine learning detector utilizing Random Forest classification."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from sentinel_detection.base import BaseDetector
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES, create_deterministic_baseline_model
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class RandomForestMLDetector(BaseDetector):
    """Production inference detector for supervised Random Forest threat classification."""

    SEVERITY_MAPPING: Dict[ThreatType, DetectionSeverity] = {
        ThreatType.SYN_FLOOD: DetectionSeverity.HIGH,
        ThreatType.UDP_FLOOD: DetectionSeverity.HIGH,
        ThreatType.PORT_SCAN: DetectionSeverity.MEDIUM,
        ThreatType.C2_BEACONING: DetectionSeverity.HIGH,
        ThreatType.DNS_DGA: DetectionSeverity.MEDIUM,
        ThreatType.DNS_TUNNELING: DetectionSeverity.HIGH,
        ThreatType.SUSPICIOUS_TLS: DetectionSeverity.MEDIUM,
        ThreatType.DATA_EXFILTRATION: DetectionSeverity.HIGH,
        ThreatType.BEHAVIORAL_ANOMALY: DetectionSeverity.MEDIUM,
        ThreatType.BENIGN: DetectionSeverity.INFO,
    }

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        model: Optional[RandomForestClassifier] = None,
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

        # Load or initialize model and metadata
        if model is not None and metadata is not None:
            self.model = model
            self.metadata = metadata
        elif model_path is not None and metadata_path is not None:
            self.model, self.metadata = self._load_model_artifacts(model_path, metadata_path)
        else:
            # Deterministic baseline fixture fallback
            self.model, self.metadata = create_deterministic_baseline_model()

    def _load_model_artifacts(
        self,
        model_path: Union[str, Path],
        metadata_path: Union[str, Path],
    ) -> Tuple[RandomForestClassifier, MLModelMetadata]:
        m_path = Path(model_path)
        meta_path = Path(metadata_path)

        if not m_path.exists():
            raise FileNotFoundError(f"ML model file not found: {m_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"ML metadata file not found: {meta_path}")

        model = joblib.load(m_path)
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = MLModelMetadata.model_validate_json(f.read())

        return model, metadata

    @property
    def detector_name(self) -> str:
        return f"ml_{self.metadata.model_name}"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.ML

    @property
    def threat_type(self) -> ThreatType:
        # ML detector can classify multiple threat types dynamically
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
        imputed_features: List[str] = []
        feature_vector: List[float] = []

        # Validate feature ordering and handle missing features safely
        for feat_name in self.metadata.feature_names:
            val = flat_features.get(feat_name)
            if val is None or not isinstance(val, (int, float)):
                # Missing feature imputation with neutral 0.0
                feature_vector.append(0.0)
                imputed_features.append(feat_name)
            else:
                feature_vector.append(float(val))

        X = np.array([feature_vector], dtype=np.float64)

        # Execute deterministic inference
        probabilities = self.model.predict_proba(X)[0]
        classes = self.metadata.target_classes

        best_idx = int(np.argmax(probabilities))
        best_class = classes[best_idx]
        best_prob = float(probabilities[best_idx])

        # If highest probability is BENIGN or fails confidence threshold, do not emit alert
        if best_class == "BENIGN" or best_prob < self.min_confidence:
            return None

        try:
            detected_threat = ThreatType(best_class)
        except ValueError:
            detected_threat = ThreatType.BEHAVIORAL_ANOMALY

        # Feature contribution analysis for explainability
        # Utilizing model feature importances scaled by observed feature magnitude
        evidence: List[DetectionEvidence] = []
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            # Rank features by contribution
            ranked_indices = np.argsort(importances)[::-1]
            top_indices = ranked_indices[:3]

            for idx in top_indices:
                feat_name = self.metadata.feature_names[idx]
                feat_val = feature_vector[idx]
                importance = importances[idx]
                evidence.append(
                    DetectionEvidence(
                        feature_name=feat_name,
                        observed_value=round(feat_val, 4),
                        threshold_value=f"feature_importance={importance:.3f}",
                        description=(
                            f"Key decision factor '{feat_name}' (weight {importance:.1%}) "
                            f"supported {detected_threat.value} classification"
                        ),
                    )
                )

        severity = self.SEVERITY_MAPPING.get(detected_threat, DetectionSeverity.MEDIUM)
        prob_dict = {classes[i]: round(float(probabilities[i]), 4) for i in range(len(classes))}

        return DetectionSignal(
            signal_id=self._generate_signal_id(),
            threat_type=detected_threat,
            detector_type=DetectorType.ML,
            detector_name=self.detector_name,
            confidence=round(best_prob, 3),
            severity=severity,
            evidence=evidence,
            description=(
                f"ML classifier ({self.metadata.model_name} v{self.metadata.model_version}) "
                f"predicted {detected_threat.value} with {best_prob:.1%} confidence"
            ),
            metadata={
                "model_name": self.metadata.model_name,
                "model_version": self.metadata.model_version,
                "class_probabilities": prob_dict,
                "imputed_features": imputed_features,
            },
        )

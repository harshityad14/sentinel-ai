"""Statistical and behavioral anomaly detector using Z-score deviations and baseline profiling."""

import math
from typing import Any, Dict, List, Optional, Tuple
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class StatisticalAnomalyDetector(BaseDetector):
    """Detects behavioral anomalies via robust statistical baseline profiling (Z-score deviation)."""

    DEFAULT_BASELINE: Dict[str, Tuple[float, float]] = {
        # feature_key: (mean, std)
        "network.duration_sec": (5.0, 10.0),
        "network.bytes_per_second": (1500.0, 5000.0),
        "network.packets_per_second": (10.0, 25.0),
        "network.mean_packet_size": (350.0, 400.0),
        "network.forward_bytes": (5000.0, 15000.0),
        "timing.mean_inter_arrival_sec": (0.2, 0.5),
    }

    def __init__(
        self,
        z_threshold: float = 3.5,
        min_deviating_features: int = 1,
        baseline_profile: Optional[Dict[str, Tuple[float, float]]] = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            z_threshold=z_threshold,
            min_deviating_features=min_deviating_features,
        )
        self.z_threshold = z_threshold
        self.min_deviating_features = min_deviating_features
        self.baseline_profile = baseline_profile or dict(self.DEFAULT_BASELINE)

    @property
    def detector_name(self) -> str:
        return "statistical_zscore_anomaly"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.STATISTICAL

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.BEHAVIORAL_ANOMALY

    def update_baseline(self, feature_vectors: List[FeatureVector]) -> None:
        """Update or fit baseline distribution parameters from a sample of normal feature vectors."""
        if not feature_vectors:
            return

        values_map: Dict[str, List[float]] = {k: [] for k in self.baseline_profile.keys()}

        for fv in feature_vectors:
            extracted = self._extract_features(fv)
            for k, val in extracted.items():
                if val is not None and not math.isnan(val):
                    values_map.setdefault(k, []).append(float(val))

        new_baseline: Dict[str, Tuple[float, float]] = {}
        for k, vals in values_map.items():
            if len(vals) >= 2:
                mean = sum(vals) / len(vals)
                variance = sum((x - mean) ** 2 for x in vals) / (len(vals) - 1)
                std = math.sqrt(variance)
                new_baseline[k] = (mean, max(std, 1e-4))
            elif k in self.baseline_profile:
                new_baseline[k] = self.baseline_profile[k]

        self.baseline_profile = new_baseline

    def _extract_features(self, features: FeatureVector) -> Dict[str, Optional[float]]:
        """Extract monitored numerical metrics for statistical profiling."""
        metrics: Dict[str, Optional[float]] = {
            "network.duration_sec": features.network.duration_sec,
            "network.bytes_per_second": features.network.bytes_per_second,
            "network.packets_per_second": features.network.packets_per_second,
            "network.mean_packet_size": features.network.mean_packet_size,
            "network.forward_bytes": float(features.network.forward_bytes),
            "timing.mean_inter_arrival_sec": features.timing.mean_inter_arrival_sec,
        }
        return metrics

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled:
            return None

        extracted = self._extract_features(features)
        evidence: List[DetectionEvidence] = []
        z_scores: Dict[str, float] = {}

        for feature_name, observed in extracted.items():
            if observed is None or math.isnan(observed):
                continue

            if feature_name not in self.baseline_profile:
                continue

            mean, std = self.baseline_profile[feature_name]
            if std <= 0.0:
                std = 1e-4

            z = (observed - mean) / std
            z_scores[feature_name] = round(z, 2)

            if abs(z) >= self.z_threshold:
                direction = "higher" if z > 0 else "lower"
                evidence.append(
                    DetectionEvidence(
                        feature_name=feature_name,
                        observed_value=round(observed, 4),
                        threshold_value=f"|z| >= {self.z_threshold} (baseline μ={round(mean, 2)}, σ={round(std, 2)})",
                        description=f"{feature_name} is {round(abs(z), 2)} std devs {direction} than baseline",
                    )
                )

        if len(evidence) < self.min_deviating_features:
            return None

        # Calculate confidence from the highest magnitude Z-score
        max_z = max(abs(z) for z in z_scores.values()) if z_scores else 0.0
        # Confidence maps sigmoid-like between 0.65 (at z_threshold) and 0.96 (at z=10+)
        norm_factor = min(1.0, (max_z - self.z_threshold) / 6.0)
        confidence = round(min(0.96, 0.65 + norm_factor * 0.31), 2)

        # Severity determined by magnitude of statistical deviation
        if max_z >= 8.0:
            severity = DetectionSeverity.HIGH
        elif max_z >= 5.0:
            severity = DetectionSeverity.MEDIUM
        else:
            severity = DetectionSeverity.LOW

        deviated_keys = [ev.feature_name for ev in evidence]
        return DetectionSignal(
            signal_id=self._generate_signal_id(),
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            detector_type=DetectorType.STATISTICAL,
            detector_name=self.detector_name,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            description=(
                f"Statistical anomaly detected across {len(evidence)} metric(s): "
                f"{', '.join(deviated_keys)} (max z-score: {max_z:.1f})"
            ),
            metadata={
                "max_z_score": max_z,
                "deviating_metrics": deviated_keys,
                "z_scores": z_scores,
                "baseline_profile": {k: {"mean": round(v[0], 2), "std": round(v[1], 2)} for k, v in self.baseline_profile.items()},
            },
        )

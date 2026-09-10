"""Ensemble correlation engine combining signals from Rule, Statistical, and ML detectors."""

from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sentinel_detection.scoring.severity_policy import evaluate_severity
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionResult,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class EnsembleCorrelationEngine:
    """Combines individual detection signals into a unified, correlated detection result."""

    DEFAULT_DETECTOR_WEIGHTS: Dict[DetectorType, float] = {
        DetectorType.RULE: 0.45,
        DetectorType.ML: 0.35,
        DetectorType.STATISTICAL: 0.20,
        DetectorType.ENSEMBLE: 0.0,
    }

    def __init__(
        self,
        detector_weights: Optional[Dict[DetectorType, float]] = None,
        agreement_bonus: float = 0.10,
        min_consensus_confidence: float = 0.50,
    ) -> None:
        """Initialize the ensemble correlation engine.

        Formula:
            Base Confidence = Sum(max_conf_by_type * weight_by_type) / Sum(weight_by_type)
            Combined Confidence = Min(0.99, Base Confidence + (agreeing_detector_types - 1) * agreement_bonus)
        """
        self.detector_weights = detector_weights or dict(self.DEFAULT_DETECTOR_WEIGHTS)
        self.agreement_bonus = agreement_bonus
        self.min_consensus_confidence = min_consensus_confidence

    def correlate(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        signals: List[DetectionSignal],
        context: Optional[Dict[str, Any]] = None,
    ) -> DetectionResult:
        """Correlate multiple detection signals for a single flow session into a DetectionResult."""
        ctx = dict(context or {})
        ctx.update({
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol.value,
        })

        detection_id = f"det_{uuid.uuid4().hex[:12]}"

        # 1. Handle benign / no signals
        if not signals:
            return DetectionResult(
                detection_id=detection_id,
                flow_id=flow.flow_id,
                threat_type=ThreatType.BENIGN,
                detector_type=DetectorType.ENSEMBLE,
                confidence=0.0,
                severity=DetectionSeverity.INFO,
                evidence=[],
                signals=[],
                feature_version=features.feature_version,
                explanation="No anomalous or malicious indicators observed across all active detectors.",
                context=ctx,
            )

        # 2. Single signal fast-path (preserves original detector type)
        if len(signals) == 1:
            sig = signals[0]
            if sig.confidence < self.min_consensus_confidence:
                return DetectionResult(
                    detection_id=detection_id,
                    flow_id=flow.flow_id,
                    threat_type=ThreatType.BENIGN,
                    detector_type=sig.detector_type,
                    confidence=sig.confidence,
                    severity=DetectionSeverity.INFO,
                    evidence=sig.evidence,
                    signals=signals,
                    feature_version=features.feature_version,
                    explanation=f"Single signal ({sig.detector_name}) fell below consensus confidence threshold ({sig.confidence:.2f} < {self.min_consensus_confidence:.2f})",
                    context=ctx,
                )

            return DetectionResult(
                detection_id=detection_id,
                flow_id=flow.flow_id,
                threat_type=sig.threat_type,
                detector_type=sig.detector_type,
                confidence=sig.confidence,
                severity=sig.severity,
                evidence=sig.evidence,
                signals=signals,
                feature_version=features.feature_version,
                explanation=sig.description,
                context=ctx,
            )

        # 3. Multi-signal grouping by threat type
        grouped: Dict[ThreatType, List[DetectionSignal]] = {}
        for sig in signals:
            grouped.setdefault(sig.threat_type, []).append(sig)

        scored_threats: List[Tuple[ThreatType, float, List[DetectionSignal], Set[DetectorType]]] = []

        for threat, threat_sigs in grouped.items():
            conf, det_types = self._calculate_ensemble_confidence(threat_sigs)
            scored_threats.append((threat, conf, threat_sigs, det_types))

        # Sort by confidence descending, then by number of agreeing detector types
        scored_threats.sort(key=lambda item: (item[1], len(item[3])), reverse=True)

        winning_threat, win_conf, win_sigs, win_types = scored_threats[0]

        # Consolidate evidence deduplicated by feature name
        seen_evidence: Set[str] = set()
        consolidated_evidence: List[DetectionEvidence] = []
        for sig in signals:
            for ev in sig.evidence:
                key = f"{ev.feature_name}:{ev.observed_value}"
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    consolidated_evidence.append(ev)

        # Evaluate consensus severity
        consensus_severity = evaluate_severity(
            threat_type=winning_threat,
            confidence=win_conf,
            evidence=consolidated_evidence,
            context=ctx,
        )

        detector_names = [s.detector_name for s in signals]
        explanation = (
            f"Ensemble detected {winning_threat.value} with {win_conf:.1%} confidence "
            f"across {len(signals)} signal(s) from {len(win_types)} detector category(ies): "
            f"[{', '.join(detector_names)}]"
        )

        # Extract ML model version if present in ML signals
        ml_model_version: Optional[str] = None
        for s in signals:
            if s.detector_type == DetectorType.ML and "model_version" in s.metadata:
                ml_model_version = str(s.metadata["model_version"])
                break

        return DetectionResult(
            detection_id=detection_id,
            flow_id=flow.flow_id,
            threat_type=winning_threat,
            detector_type=DetectorType.ENSEMBLE,
            confidence=round(win_conf, 4),
            severity=consensus_severity,
            evidence=consolidated_evidence,
            signals=signals,
            feature_version=features.feature_version,
            model_version=ml_model_version,
            explanation=explanation,
            context=ctx,
        )

    def _calculate_ensemble_confidence(
        self, signals: List[DetectionSignal]
    ) -> Tuple[float, Set[DetectorType]]:
        """Calculate weighted confidence and agreement boost for signals of the same threat type."""
        # Find maximum confidence per detector type
        type_max_conf: Dict[DetectorType, float] = {}
        for sig in signals:
            type_max_conf[sig.detector_type] = max(
                type_max_conf.get(sig.detector_type, 0.0), sig.confidence
            )

        contributing_types = set(type_max_conf.keys())

        # Weighted combination
        total_weight = sum(self.detector_weights.get(dt, 0.25) for dt in contributing_types)
        if total_weight <= 0.0:
            total_weight = 1.0

        weighted_sum = sum(
            type_max_conf[dt] * self.detector_weights.get(dt, 0.25) for dt in contributing_types
        )
        base_confidence = weighted_sum / total_weight

        # Multi-detector agreement bonus
        if len(contributing_types) > 1:
            boost = (len(contributing_types) - 1) * self.agreement_bonus
            combined_confidence = min(0.99, base_confidence + boost)
        else:
            combined_confidence = base_confidence

        return combined_confidence, contributing_types

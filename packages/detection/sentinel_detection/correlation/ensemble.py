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

            # Rule-only threat -> alert remains valid with original detector type and severity
            if sig.detector_type == DetectorType.RULE:
                return DetectionResult(
                    detection_id=detection_id,
                    flow_id=flow.flow_id,
                    threat_type=sig.threat_type,
                    detector_type=DetectorType.RULE,
                    confidence=sig.confidence,
                    severity=sig.severity,
                    evidence=sig.evidence,
                    signals=signals,
                    feature_version=features.feature_version,
                    explanation=f"Deterministic rule ({sig.detector_name}) detected authoritative threat {sig.threat_type.value} with {sig.confidence:.1%} confidence",
                    context=ctx,
                )

            # Borderline ML prediction without corroboration -> low-priority investigation signal
            if sig.detector_type == DetectorType.ML and sig.metadata.get("is_borderline", False):
                thresh = sig.metadata.get("calibrated_threshold", self.min_consensus_confidence)
                return DetectionResult(
                    detection_id=detection_id,
                    flow_id=flow.flow_id,
                    threat_type=sig.threat_type,
                    detector_type=DetectorType.ML,
                    confidence=sig.confidence,
                    severity=DetectionSeverity.LOW,
                    evidence=sig.evidence,
                    signals=signals,
                    feature_version=features.feature_version,
                    model_version=str(sig.metadata.get("model_version", "")) or None,
                    explanation=(
                        f"Uncorroborated borderline ML prediction for {sig.threat_type.value} "
                        f"({sig.confidence:.1%} < calibrated threshold {thresh:.2f}) retained as "
                        f"low-priority investigation signal without alert escalation"
                    ),
                    context=ctx,
                )

            # IF anomaly alone -> investigation signal
            if sig.detector_type == DetectorType.STATISTICAL and sig.threat_type == ThreatType.BEHAVIORAL_ANOMALY:
                return DetectionResult(
                    detection_id=detection_id,
                    flow_id=flow.flow_id,
                    threat_type=ThreatType.BEHAVIORAL_ANOMALY,
                    detector_type=DetectorType.STATISTICAL,
                    confidence=sig.confidence,
                    severity=DetectionSeverity.LOW,
                    evidence=sig.evidence,
                    signals=signals,
                    feature_version=features.feature_version,
                    explanation=(
                        f"Unsupervised anomaly signal ({sig.detector_name}) flagged "
                        f"out-of-distribution traffic (confidence={sig.confidence:.1%}) "
                        f"as behavioral investigation signal"
                    ),
                    context=ctx,
                )

            # Strong ML prediction with no rule -> retain detection without unnecessary escalation
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
                model_version=str(sig.metadata.get("model_version", "")) or None,
                explanation=sig.description,
                context=ctx,
            )

        # 3. Multi-signal grouping and conservative fusion
        # Separate unsupervised anomaly signals (Isolation Forest / STATISTICAL)
        anomaly_sigs = [
            s for s in signals
            if s.detector_type == DetectorType.STATISTICAL and s.threat_type == ThreatType.BEHAVIORAL_ANOMALY
        ]
        non_anomaly_sigs = [
            s for s in signals
            if not (s.detector_type == DetectorType.STATISTICAL and s.threat_type == ThreatType.BEHAVIORAL_ANOMALY)
        ]

        # Case: ONLY unsupervised anomaly signals were emitted
        if not non_anomaly_sigs and anomaly_sigs:
            best_anom = max(anomaly_sigs, key=lambda s: s.confidence)
            return DetectionResult(
                detection_id=detection_id,
                flow_id=flow.flow_id,
                threat_type=ThreatType.BEHAVIORAL_ANOMALY,
                detector_type=DetectorType.STATISTICAL,
                confidence=best_anom.confidence,
                severity=DetectionSeverity.LOW,
                evidence=best_anom.evidence,
                signals=signals,
                feature_version=features.feature_version,
                explanation=(
                    f"Unsupervised anomaly signal ({best_anom.detector_name}) flagged "
                    f"out-of-distribution traffic (confidence={best_anom.confidence:.1%}) "
                    f"as behavioral investigation signal"
                ),
                context=ctx,
            )

        # Group non-anomaly signals by threat type
        grouped: Dict[ThreatType, List[DetectionSignal]] = {}
        for sig in non_anomaly_sigs:
            grouped.setdefault(sig.threat_type, []).append(sig)

        scored_threats: List[Tuple[ThreatType, float, List[DetectionSignal], Set[DetectorType], bool]] = []
        # (threat, conf, threat_sigs, det_types, is_borderline_ml)

        for threat, threat_sigs in grouped.items():
            conf, det_types = self._calculate_ensemble_confidence(threat_sigs)
            has_rule = (DetectorType.RULE in det_types)
            has_ml = (DetectorType.ML in det_types)
            is_borderline_ml = False
            if has_ml and not has_rule:
                ml_sigs_for_threat = [s for s in threat_sigs if s.detector_type == DetectorType.ML]
                if all(s.metadata.get("is_borderline", False) for s in ml_sigs_for_threat):
                    is_borderline_ml = True
            scored_threats.append((threat, conf, threat_sigs, det_types, is_borderline_ml))

        # Rule priority: If a deterministic rule fired with high confidence (>= 0.70),
        # it is authoritative and prioritized over uncorroborated ML predictions
        rule_threats = [t for t, conf, sigs, types, is_bord in scored_threats if DetectorType.RULE in types and conf >= 0.70]
        if rule_threats:
            # Reorder scored_threats so high-confidence rule threats are first, followed by multi-detector agreement
            scored_threats.sort(
                key=lambda item: (
                    DetectorType.RULE in item[3] and item[1] >= 0.70,
                    len(item[3]) > 1,
                    item[1],
                ),
                reverse=True,
            )
        else:
            # If no high-confidence rule: prioritize non-borderline or corroborated threats
            scored_threats.sort(
                key=lambda item: (
                    not item[4] or bool(anomaly_sigs),
                    len(item[3]) > 1,
                    item[1],
                ),
                reverse=True,
            )

        winning_threat, win_conf, win_sigs, win_types, is_borderline_ml = scored_threats[0]

        # Anomaly corroboration: If an unsupervised anomaly signal (STATISTICAL) also fired on this flow,
        # it provides independent corroborating evidence of abnormality for specific attacks
        corroborated_by_if = False
        if anomaly_sigs and winning_threat != ThreatType.BEHAVIORAL_ANOMALY:
            win_types.add(DetectorType.STATISTICAL)
            win_conf = min(0.99, win_conf + self.agreement_bonus * 0.5)
            corroborated_by_if = True
            # Borderline ML is now corroborated by IF anomaly
            is_borderline_ml = False

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
        if is_borderline_ml and not corroborated_by_if and DetectorType.RULE not in win_types:
            consensus_severity = DetectionSeverity.LOW
        else:
            consensus_severity = evaluate_severity(
                threat_type=winning_threat,
                confidence=win_conf,
                evidence=consolidated_evidence,
                context=ctx,
            )

        detector_names = [s.detector_name for s in signals]
        layer_summary = ", ".join(sorted(dt.value for dt in win_types))

        explanation_notes = []
        if DetectorType.RULE in win_types and DetectorType.ML in win_types:
            explanation_notes.append("RF+Rule agreement corroborated")
        if corroborated_by_if:
            explanation_notes.append("Isolation Forest anomaly corroboration")
        if is_borderline_ml:
            explanation_notes.append("Uncorroborated borderline ML prediction retained as investigation signal")

        notes_str = f" ({'; '.join(explanation_notes)})" if explanation_notes else ""
        explanation = (
            f"Ensemble detected {winning_threat.value} with {win_conf:.1%} confidence "
            f"across {len(signals)} signal(s) from layers [{layer_summary}]: "
            f"[{', '.join(detector_names)}]{notes_str}"
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
            detector_type=DetectorType.ENSEMBLE if len(win_types) > 1 else list(win_types)[0],
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

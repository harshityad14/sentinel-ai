"""Deterministic multi-factor risk calculator for SentinelAI security alerts.

PRINCIPLE:
Risk score (0 - 100) measures overall prioritization by combining confidence,
severity impact, multi-detector agreement, signal volume, recurrence, and temporal proximity.
Confidence and Severity are preserved separately and remain independent metrics.
"""

import math
from typing import Any, Dict, List, Optional, Set, Union

from sentinel_detection.correlation.config import CorrelationConfig
from sentinel_models.alerts import AlertSeverity, RiskScore
from sentinel_models.detection import DetectionSeverity, DetectorType


class RiskCalculator:
    """Calculates deterministic, bounded (0 - 100), explainable risk scores."""

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00,
    }

    def __init__(self, config: Optional[CorrelationConfig] = None) -> None:
        self.config = config or CorrelationConfig()

    def calculate_risk(
        self,
        confidence: float,
        severity: Union[AlertSeverity, DetectionSeverity, str],
        detector_types: Optional[Union[List[Union[DetectorType, str]], Set[Union[DetectorType, str]]]] = None,
        signal_count: int = 1,
        recurrence_count: int = 1,
        time_delta_sec: float = 0.0,
    ) -> RiskScore:
        """Compute an objective multi-factor risk score with an explainable breakdown."""
        cfg = self.config

        # 1. Confidence factor (0.0 to 1.0)
        f_conf = max(0.0, min(1.0, float(confidence)))

        # 2. Severity factor (0.25 to 1.0)
        sev_key = severity.value if hasattr(severity, "value") else str(severity).upper()
        f_sev = self.SEVERITY_WEIGHTS.get(sev_key, 0.50)

        # 3. Multi-detector category agreement factor (0.4 to 1.0)
        types_set = {
            dt.value if hasattr(dt, "value") else str(dt).upper()
            for dt in (detector_types or [])
        }
        distinct_types = len(types_set)
        if distinct_types >= 3:
            f_agree = 1.00
        elif distinct_types == 2:
            f_agree = 0.75
        elif distinct_types == 1:
            f_agree = 0.40
        else:
            f_agree = 0.30

        # 4. Signal volume saturation factor (0.0 to 1.0)
        # Asymptotic curve: 1 signal -> 0.0, 5 signals -> ~0.55, 15+ signals -> ~0.95
        f_signals = 1.0 - math.exp(-0.20 * max(0, signal_count - 1))

        # 5. Recurrence factor (0.0 to 1.0)
        # Repeated alerts from same entity increase operational risk
        f_recurrence = min(1.0, max(0.0, (recurrence_count - 1) / 10.0))

        # 6. Temporal proximity factor (0.1 to 1.0)
        # Bursts clustered closely in time represent elevated urgency
        proximity = max(0.0, 1.0 - (time_delta_sec / max(1.0, cfg.time_window_sec)))
        f_temporal = max(0.10, min(1.0, proximity))

        # Weighted combination
        w_conf = cfg.risk_weight_confidence
        w_sev = cfg.risk_weight_severity
        w_agree = cfg.risk_weight_agreement
        w_sig = cfg.risk_weight_signal_count
        w_rec = cfg.risk_weight_recurrence
        w_temp = cfg.risk_weight_temporal_proximity

        raw_points = (
            w_conf * f_conf
            + w_sev * f_sev
            + w_agree * f_agree
            + w_sig * f_signals
            + w_rec * f_recurrence
            + w_temp * f_temporal
        )
        final_score = int(round(max(0.0, min(100.0, raw_points * 100.0))))

        breakdown = {
            "confidence_points": round(w_conf * f_conf * 100.0, 1),
            "severity_points": round(w_sev * f_sev * 100.0, 1),
            "agreement_points": round(w_agree * f_agree * 100.0, 1),
            "signal_count_points": round(w_sig * f_signals * 100.0, 1),
            "recurrence_points": round(w_rec * f_recurrence * 100.0, 1),
            "temporal_points": round(w_temp * f_temporal * 100.0, 1),
        }

        explanation = (
            f"Risk score {final_score}/100: "
            f"severity ({sev_key}={breakdown['severity_points']} pts), "
            f"confidence ({f_conf:.0%}={breakdown['confidence_points']} pts), "
            f"agreement ({distinct_types} categories={breakdown['agreement_points']} pts), "
            f"volume ({signal_count} signals={breakdown['signal_count_points']} pts), "
            f"recurrence ({recurrence_count}x={breakdown['recurrence_points']} pts)"
        )

        return RiskScore(
            score=final_score,
            confidence_factor=round(f_conf, 4),
            severity_factor=round(f_sev, 4),
            agreement_factor=round(f_agree, 4),
            signal_count_factor=round(f_signals, 4),
            recurrence_factor=round(f_recurrence, 4),
            temporal_proximity_factor=round(f_temporal, 4),
            breakdown=breakdown,
            explanation=explanation,
        )

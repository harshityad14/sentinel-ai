"""C2 Beaconing timing jitter rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class C2BeaconingRuleDetector(BaseDetector):
    """Detects periodic Command & Control (C2) keep-alive heartbeats via timing jitter analysis."""

    def __init__(
        self,
        max_jitter_ratio: float = 0.15,
        min_packets: int = 6,
        min_interval_sec: float = 1.0,
        max_interval_sec: float = 300.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            max_jitter_ratio=max_jitter_ratio,
            min_packets=min_packets,
            min_interval_sec=min_interval_sec,
            max_interval_sec=max_interval_sec,
        )
        self.max_jitter_ratio = max_jitter_ratio
        self.min_packets = min_packets
        self.min_interval_sec = min_interval_sec
        self.max_interval_sec = max_interval_sec

    @property
    def detector_name(self) -> str:
        return "c2_beaconing_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.C2_BEACONING

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or features.timing.jitter_ratio is None:
            return None

        jitter = features.timing.jitter_ratio
        mean_iat = features.timing.mean_inter_arrival_sec
        tot_pkts = features.network.total_packets

        # Skip known legitimate periodic protocols like NTP (port 123)
        if flow.destination_port == 123 or flow.source_port == 123:
            return None

        # C2 pattern: low timing jitter (<15%), steady period within interval range, sustained connection sequence
        interval = context.get("interval_sec", mean_iat) if context else mean_iat
        if (
            tot_pkts >= self.min_packets
            and self.min_interval_sec <= interval <= self.max_interval_sec
            and jitter <= self.max_jitter_ratio
        ):
            confidence = min(0.92, 0.75 + (1.0 - (jitter / self.max_jitter_ratio)) * 0.17)
            severity = DetectionSeverity.HIGH

            evidence = [
                DetectionEvidence(
                    feature_name="time_jitter_ratio",
                    observed_value=jitter,
                    threshold_value=self.max_jitter_ratio,
                    description=f"Extremely low timing jitter ({jitter:.2%}) indicates automated programmatic pacing",
                ),
                DetectionEvidence(
                    feature_name="time_mean_inter_arrival_sec",
                    observed_value=mean_iat,
                    threshold_value=f"[{self.min_interval_sec}s, {self.max_interval_sec}s]",
                    description=f"Periodic heartbeat interval observed ({mean_iat:.2f}s)",
                ),
                DetectionEvidence(
                    feature_name="net_total_packets",
                    observed_value=tot_pkts,
                    threshold_value=self.min_packets,
                    description=f"Sustained heartbeat count ({tot_pkts} packets)",
                ),
            ]

            return DetectionSignal(
                signal_id=self._generate_signal_id(),
                threat_type=self.threat_type,
                detector_type=self.detector_type,
                detector_name=self.detector_name,
                confidence=round(confidence, 4),
                severity=severity,
                evidence=evidence,
                description=f"Suspected C2 beaconing channel established to {flow.destination_ip}:{flow.destination_port} (period: {mean_iat:.2f}s, jitter: {jitter:.1%})",
                metadata={"destination_ip": flow.destination_ip, "period_sec": mean_iat, "jitter": jitter},
            )

        return None

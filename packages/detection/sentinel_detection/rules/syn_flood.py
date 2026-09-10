"""SYN Flood volumetric rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector


class SYNFloodRuleDetector(BaseDetector):
    """Detects TCP SYN Flood denial-of-service volumetric bursts."""

    def __init__(
        self,
        min_syn_count: int = 20,
        min_syn_ack_ratio: float = 5.0,
        min_pps: float = 30.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_syn_count=min_syn_count,
            min_syn_ack_ratio=min_syn_ack_ratio,
            min_pps=min_pps,
        )
        self.min_syn_count = min_syn_count
        self.min_syn_ack_ratio = min_syn_ack_ratio
        self.min_pps = min_pps

    @property
    def detector_name(self) -> str:
        return "syn_flood_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.SYN_FLOOD

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or flow.protocol != ProtocolType.TCP or features.tcp is None:
            return None

        syn_count = features.tcp.syn_count
        syn_ack_r = features.tcp.syn_ack_ratio
        pps = features.network.packets_per_second

        # Threshold evaluation
        if syn_count >= self.min_syn_count and syn_ack_r >= self.min_syn_ack_ratio and pps >= self.min_pps:
            confidence = min(0.98, 0.80 + (syn_ack_r / 50.0) * 0.18)
            severity = DetectionSeverity.CRITICAL if syn_count >= 100 else DetectionSeverity.HIGH

            evidence = [
                DetectionEvidence(
                    feature_name="tcp_syn_count",
                    observed_value=syn_count,
                    threshold_value=self.min_syn_count,
                    description=f"High SYN flag count ({syn_count}) observed in TCP session",
                ),
                DetectionEvidence(
                    feature_name="tcp_syn_ack_ratio",
                    observed_value=syn_ack_r,
                    threshold_value=self.min_syn_ack_ratio,
                    description=f"Severe SYN-to-ACK imbalance ({syn_ack_r:.2f}:1)",
                ),
                DetectionEvidence(
                    feature_name="net_packets_per_second",
                    observed_value=pps,
                    threshold_value=self.min_pps,
                    description=f"Elevated packet arrival rate ({pps:.1f} pkts/sec)",
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
                description=f"Potential SYN flood DoS attack detected against {flow.destination_ip}:{flow.destination_port}",
                metadata={"destination_ip": flow.destination_ip, "destination_port": flow.destination_port},
            )

        return None

"""UDP Flood volumetric rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector


class UDPFloodRuleDetector(BaseDetector):
    """Detects high-volume UDP flood volumetric denial-of-service traffic."""

    def __init__(
        self,
        min_packets: int = 50,
        min_pps: float = 100.0,
        min_bps: float = 20000.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_packets=min_packets,
            min_pps=min_pps,
            min_bps=min_bps,
        )
        self.min_packets = min_packets
        self.min_pps = min_pps
        self.min_bps = min_bps

    @property
    def detector_name(self) -> str:
        return "udp_flood_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.UDP_FLOOD

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or flow.protocol != ProtocolType.UDP:
            return None

        tot_pkts = features.network.total_packets
        pps = features.network.packets_per_second
        bps = features.network.bytes_per_second

        if tot_pkts >= self.min_packets and pps >= self.min_pps and bps >= self.min_bps:
            confidence = min(0.95, 0.80 + (pps / 500.0) * 0.15)
            severity = DetectionSeverity.HIGH

            evidence = [
                DetectionEvidence(
                    feature_name="net_total_packets",
                    observed_value=tot_pkts,
                    threshold_value=self.min_packets,
                    description=f"Elevated UDP packet count ({tot_pkts})",
                ),
                DetectionEvidence(
                    feature_name="net_packets_per_second",
                    observed_value=pps,
                    threshold_value=self.min_pps,
                    description=f"UDP packet rate ({pps:.1f} pkts/sec) breached threshold",
                ),
                DetectionEvidence(
                    feature_name="net_bytes_per_second",
                    observed_value=bps,
                    threshold_value=self.min_bps,
                    description=f"UDP byte rate ({bps:.1f} Bps) breached threshold",
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
                description=f"UDP flood volumetric attack detected against {flow.destination_ip}:{flow.destination_port}",
                metadata={"destination_ip": flow.destination_ip, "destination_port": flow.destination_port},
            )

        return None

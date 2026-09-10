"""Data Exfiltration heuristic rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class DataExfiltrationRuleDetector(BaseDetector):
    """Detects suspicious bulk outbound data exfiltration transfers."""

    def __init__(
        self,
        min_outbound_bytes: int = 250_000,
        min_byte_asymmetry_ratio: float = 0.85,
        min_bps: float = 5_000.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_outbound_bytes=min_outbound_bytes,
            min_byte_asymmetry_ratio=min_byte_asymmetry_ratio,
            min_bps=min_bps,
        )
        self.min_outbound_bytes = min_outbound_bytes
        self.min_byte_asymmetry_ratio = min_byte_asymmetry_ratio
        self.min_bps = min_bps

    @property
    def detector_name(self) -> str:
        return "data_exfiltration_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.DATA_EXFILTRATION

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled:
            return None

        fwd_bytes = features.network.forward_bytes
        asym_ratio = features.network.byte_asymmetry_ratio
        bps = features.network.bytes_per_second

        # Exfiltration pattern: massive outbound volume with severe directional byte asymmetry
        if fwd_bytes >= self.min_outbound_bytes and asym_ratio >= self.min_byte_asymmetry_ratio and bps >= self.min_bps:
            confidence = min(0.88, 0.70 + (asym_ratio - self.min_byte_asymmetry_ratio) * 0.50 + (fwd_bytes / 5_000_000) * 0.10)
            severity = DetectionSeverity.HIGH if fwd_bytes >= 1_000_000 else DetectionSeverity.MEDIUM

            evidence = [
                DetectionEvidence(
                    feature_name="net_forward_bytes",
                    observed_value=fwd_bytes,
                    threshold_value=self.min_outbound_bytes,
                    description=f"High outbound data transfer volume ({fwd_bytes:,} bytes)",
                ),
                DetectionEvidence(
                    feature_name="net_byte_asymmetry_ratio",
                    observed_value=asym_ratio,
                    threshold_value=self.min_byte_asymmetry_ratio,
                    description=f"Strong outbound-to-inbound byte asymmetry ({asym_ratio:.2%})",
                ),
                DetectionEvidence(
                    feature_name="net_bytes_per_second",
                    observed_value=bps,
                    threshold_value=self.min_bps,
                    description=f"Sustained transfer velocity ({bps:,.1f} Bps)",
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
                description=f"Suspicious high-volume outbound data transfer to {flow.destination_ip}:{flow.destination_port} ({fwd_bytes:,} bytes, asymmetry: {asym_ratio:.1%})",
                metadata={"destination_ip": flow.destination_ip, "forward_bytes": fwd_bytes},
            )

        return None

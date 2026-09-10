"""Correlated Port & Network Scan rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector


class PortScanRuleDetector(BaseDetector):
    """Detects horizontal and vertical port scanning activity.
    
    Architectural Invariant:
    A single isolated flow cannot reliably establish a port scan. This detector
    evaluates flow-level probe signatures (e.g. short duration, low packet counts,
    and TCP resets) in conjunction with multi-flow host context (fan-out counts).
    """

    def __init__(
        self,
        min_scanned_ports: int = 10,
        max_probe_duration_sec: float = 2.0,
        max_probe_packets: int = 4,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_scanned_ports=min_scanned_ports,
            max_probe_duration_sec=max_probe_duration_sec,
            max_probe_packets=max_probe_packets,
        )
        self.min_scanned_ports = min_scanned_ports
        self.max_probe_duration_sec = max_probe_duration_sec
        self.max_probe_packets = max_probe_packets

    @property
    def detector_name(self) -> str:
        return "port_scan_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.PORT_SCAN

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled:
            return None

        # 1. Inspect host correlation context if available
        # Context can be supplied by session/host trackers (Phase 1/4 correlation)
        ctx = context or {}
        scanned_ports = ctx.get("scanned_ports_count", 1)
        recent_probes = ctx.get("recent_probes_count", 1)
        is_correlated_scan = (scanned_ports >= self.min_scanned_ports) or (recent_probes >= self.min_scanned_ports)

        # 2. Inspect flow-level probe kinetics
        duration = features.network.duration_sec
        total_pkts = features.network.total_packets
        is_short_probe = (duration <= self.max_probe_duration_sec) and (total_pkts <= self.max_probe_packets)

        # Check for TCP connection rejection (RST flag)
        has_rst = False
        if features.tcp:
            has_rst = features.tcp.rst_count > 0 or features.tcp.rst_ratio > 0.0

        # Strict requirement: Correlated multi-port pattern must be demonstrated
        if is_correlated_scan and (is_short_probe or has_rst):
            confidence = min(0.95, 0.70 + (scanned_ports / 50.0) * 0.25)
            severity = DetectionSeverity.HIGH if scanned_ports >= 25 else DetectionSeverity.MEDIUM

            evidence = [
                DetectionEvidence(
                    feature_name="scanned_ports_count",
                    observed_value=scanned_ports,
                    threshold_value=self.min_scanned_ports,
                    description=f"Host targeted {scanned_ports} distinct ports within observation window",
                ),
                DetectionEvidence(
                    feature_name="net_duration_sec",
                    observed_value=duration,
                    threshold_value=self.max_probe_duration_sec,
                    description=f"Short connection probe duration ({duration:.3f}s)",
                ),
                DetectionEvidence(
                    feature_name="tcp_rst_observed",
                    observed_value=has_rst,
                    threshold_value=True,
                    description="TCP RST / connection reset observed during probe",
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
                description=f"Port scan reconnaissance detected from source {flow.source_ip} (fan-out: {scanned_ports} ports)",
                metadata={"source_ip": flow.source_ip, "scanned_ports": scanned_ports},
            )

        return None

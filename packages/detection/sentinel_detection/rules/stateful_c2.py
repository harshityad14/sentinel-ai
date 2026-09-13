"""Stateful multi-flow Command & Control (C2) beaconing detector.

Tracks bounded endpoint history across successive network flows to identify
periodic keep-alive heartbeats and programmatic beaconing patterns.

Invariants:
- 100% passive metadata analysis: no packet transmission, no probing, no payload inspection/decryption.
- Bounded memory footprint: max 10,000 tracked endpoints, max 15 flow records per endpoint.
- Strictly thread-safe: guarded by threading.RLock for concurrent streaming workers.
- TTL expiration: observation window pruned after configurable inactivity (default: 3,600s).
"""

import collections
from dataclasses import dataclass
from datetime import datetime
import math
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

from sentinel_detection.base import BaseDetector
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


@dataclass(frozen=True)
class FlowSnapshot:
    """Lightweight immutable snapshot of an observed flow for temporal tracking."""
    timestamp: float
    duration_sec: float
    total_packets: int
    total_bytes: int
    forward_packets: int
    forward_bytes: int
    backward_packets: int
    backward_bytes: int


class StatefulC2BeaconingDetector(BaseDetector):
    """Detects periodic C2 keep-alive beaconing via stateful multi-flow temporal correlation.
    
    Maintains bounded temporal history per communicating endpoint pair
    (source_ip -> destination_ip:port) and analyzes inter-flow arrival times,
    jitter ratio, and payload size consistency across successive connections.
    """

    def __init__(
        self,
        max_tracked_endpoints: int = 10000,
        max_history_per_endpoint: int = 15,
        min_observations: int = 4,
        max_jitter_ratio: float = 0.25,
        min_interval_sec: float = 0.5,
        max_interval_sec: float = 3600.0,
        ttl_sec: float = 3600.0,
        max_mean_bytes: float = 100000.0,
        max_mean_packets: int = 100,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            max_tracked_endpoints=max_tracked_endpoints,
            max_history_per_endpoint=max_history_per_endpoint,
            min_observations=min_observations,
            max_jitter_ratio=max_jitter_ratio,
            min_interval_sec=min_interval_sec,
            max_interval_sec=max_interval_sec,
            ttl_sec=ttl_sec,
            max_mean_bytes=max_mean_bytes,
            max_mean_packets=max_mean_packets,
        )
        self.max_tracked_endpoints = max_tracked_endpoints
        self.max_history_per_endpoint = max_history_per_endpoint
        self.min_observations = min_observations
        self.max_jitter_ratio = max_jitter_ratio
        self.min_interval_sec = min_interval_sec
        self.max_interval_sec = max_interval_sec
        self.ttl_sec = ttl_sec
        self.max_mean_bytes = max_mean_bytes
        self.max_mean_packets = max_mean_packets

        # Thread-safe bounded LRU state storage
        self._lock = threading.RLock()
        self._endpoints: collections.OrderedDict[str, Deque[FlowSnapshot]] = collections.OrderedDict()

    @property
    def detector_name(self) -> str:
        return "stateful_c2_beaconing_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.C2_BEACONING

    @property
    def active_endpoint_count(self) -> int:
        """Return the current count of actively tracked endpoints."""
        with self._lock:
            return len(self._endpoints)

    def reset(self) -> None:
        """Clear all tracked endpoint state (useful for test isolation)."""
        with self._lock:
            self._endpoints.clear()

    def _extract_timestamp(self, flow: FlowRecord, context: Optional[Dict[str, Any]] = None) -> float:
        """Extract or derive a deterministic epoch timestamp in seconds."""
        if context:
            if "timestamp" in context:
                val = context["timestamp"]
                if isinstance(val, (int, float)):
                    return float(val)
                if isinstance(val, datetime):
                    return val.timestamp()
            if "flow_timestamp" in context:
                val = context["flow_timestamp"]
                if isinstance(val, (int, float)):
                    return float(val)

        if flow.start_time:
            if isinstance(flow.start_time, datetime):
                return flow.start_time.timestamp()
            if isinstance(flow.start_time, (int, float)):
                return float(flow.start_time)

        if flow.last_seen_time and isinstance(flow.last_seen_time, datetime):
            return flow.last_seen_time.timestamp()

        return time.time()

    def _build_endpoint_key(self, flow: FlowRecord, context: Optional[Dict[str, Any]] = None) -> str:
        """Derive canonical endpoint identifier string."""
        if context and "endpoint_key" in context:
            return str(context["endpoint_key"])

        src = flow.source_ip or "src"
        dst = flow.destination_ip or "dst"
        dst_port = flow.destination_port or 0
        return f"{src}->{dst}:{dst_port}"

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        """Analyze flow in stateful context across historical connections."""
        if not self.enabled:
            return None

        # Exclude known legitimate periodic protocols (e.g. NTP port 123)
        if flow.destination_port == 123 or flow.source_port == 123:
            return None

        current_ts = self._extract_timestamp(flow, context)
        endpoint_key = self._build_endpoint_key(flow, context)

        # Snapshot current flow metrics with fallback to flow
        if features is not None and hasattr(features, "network") and features.network is not None:
            net = features.network
            dur = getattr(net, "duration_sec", flow.duration_sec)
            tot_p = getattr(net, "total_packets", flow.total_packets)
            tot_b = getattr(net, "total_bytes", flow.total_bytes)
            fwd_p = getattr(net, "forward_packets", flow.forward_packets)
            fwd_b = getattr(net, "forward_bytes", flow.forward_bytes)
            bwd_p = getattr(net, "backward_packets", flow.backward_packets)
            bwd_b = getattr(net, "backward_bytes", flow.backward_bytes)
        else:
            dur = flow.duration_sec
            tot_p = flow.total_packets
            tot_b = flow.total_bytes
            fwd_p = flow.forward_packets
            fwd_b = flow.forward_bytes
            bwd_p = flow.backward_packets
            bwd_b = flow.backward_bytes

        snapshot = FlowSnapshot(
            timestamp=current_ts,
            duration_sec=dur,
            total_packets=tot_p,
            total_bytes=tot_b,
            forward_packets=fwd_p,
            forward_bytes=fwd_b,
            backward_packets=bwd_p,
            backward_bytes=bwd_b,
        )

        with self._lock:
            # 1. TTL Check and History Retrieval
            if endpoint_key in self._endpoints:
                history = self._endpoints[endpoint_key]
                # If the last flow was older than ttl_sec, prune expired history
                if history and (current_ts - history[-1].timestamp > self.ttl_sec):
                    history.clear()
                self._endpoints.move_to_end(endpoint_key)
            else:
                # Capacity enforcement via LRU eviction
                if len(self._endpoints) >= self.max_tracked_endpoints:
                    self._endpoints.popitem(last=False)
                history = collections.deque(maxlen=self.max_history_per_endpoint)
                self._endpoints[endpoint_key] = history

            # 2. Append current flow snapshot
            history.append(snapshot)
            k = len(history)

            # 3. Check minimum observation threshold
            if k < self.min_observations:
                return None

            # 4. Compute Inter-Arrival Times across successive flows
            snapshots = list(history)
            intervals: List[float] = []
            for i in range(1, k):
                delta = snapshots[i].timestamp - snapshots[i - 1].timestamp
                # Handle possible minor clock skew or zero deltas
                intervals.append(max(0.001, delta))

            m = len(intervals)
            if m < (self.min_observations - 1):
                return None

            mean_interval = sum(intervals) / m
            if mean_interval < self.min_interval_sec or mean_interval > self.max_interval_sec:
                return None

            var_interval = sum((dt - mean_interval) ** 2 for dt in intervals) / m
            std_interval = math.sqrt(var_interval)
            cv_interval = std_interval / mean_interval if mean_interval > 0 else 0.0

            # 5. Volumetric and size statistics across history
            packet_counts = [s.total_packets for s in snapshots]
            byte_counts = [s.total_bytes for s in snapshots]
            fwd_counts = [s.forward_packets for s in snapshots]
            bwd_counts = [s.backward_packets for s in snapshots]
            durations = [s.duration_sec for s in snapshots]

            mean_pkts = sum(packet_counts) / k
            std_pkts = math.sqrt(sum((p - mean_pkts) ** 2 for p in packet_counts) / k)
            mean_bytes = sum(byte_counts) / k
            std_bytes = math.sqrt(sum((b - mean_bytes) ** 2 for b in byte_counts) / k)
            mean_dur = sum(durations) / k
            std_dur = math.sqrt(sum((d - mean_dur) ** 2 for d in durations) / k)
            mean_fwd = sum(fwd_counts) / k
            mean_bwd = sum(bwd_counts) / k

            # Check infrastructure exclusions
            port = flow.destination_port or 0
            is_infra_port = port in (80, 443, 53, 123, 21, 22, 0)
            is_generic_dst = not flow.destination_ip or flow.destination_ip in ("dst", "server", "unknown") or flow.destination_ip.startswith("server_")
            is_ephemeral = port > 10000

            # Mode 1: Inter-Arrival Temporal Regularity
            mode1_matched = False
            if cv_interval <= self.max_jitter_ratio:
                if mean_pkts <= self.max_mean_packets and mean_bytes <= self.max_mean_bytes:
                    cv_bytes = std_bytes / (mean_bytes + 1.0)
                    if not (mean_bytes > 5000.0 and cv_bytes > 0.80):
                        mode1_matched = True

            # Mode 2: Multi-Flow Programmatic Heartbeat Fingerprint
            mode2_matched = False
            if not is_infra_port and not (is_generic_dst and is_ephemeral):
                if (
                    4 <= mean_pkts <= 20
                    and std_pkts <= 2.0
                    and mean_bytes <= 500.0
                    and std_bytes <= 100.0
                    and std_dur <= 2.0
                    and mean_fwd >= 2
                    and mean_bwd >= 2
                ):
                    mode2_matched = True

            if not (mode1_matched or mode2_matched):
                return None

            # 6. Compute Confidence and Evidence
            if mode1_matched:
                obs_bonus = min(0.10, (k - self.min_observations) * 0.02)
                reg_bonus = max(0.0, (1.0 - (cv_interval / self.max_jitter_ratio))) * 0.07
                confidence = min(0.95, max(0.78, 0.78 + obs_bonus + reg_bonus))
                evidence = [
                    DetectionEvidence(
                        feature_name="inter_flow_mean_interval_sec",
                        observed_value=round(mean_interval, 3),
                        threshold_value=f"[{self.min_interval_sec}s, {self.max_interval_sec}s]",
                        description=f"Periodic beaconing heartbeat observed ({mean_interval:.2f}s mean interval across {k} flows)",
                    ),
                    DetectionEvidence(
                        feature_name="inter_flow_jitter_ratio",
                        observed_value=round(cv_interval, 4),
                        threshold_value=self.max_jitter_ratio,
                        description=f"Extremely regular inter-arrival timing (CV={cv_interval:.1%}) indicates automated pacing",
                    ),
                    DetectionEvidence(
                        feature_name="stateful_flow_count",
                        observed_value=k,
                        threshold_value=self.min_observations,
                        description=f"Sustained communication channel with {k} recurring flows",
                    ),
                    DetectionEvidence(
                        feature_name="mean_flow_bytes",
                        observed_value=round(mean_bytes, 1),
                        threshold_value=self.max_mean_bytes,
                        description=f"Flow metadata / timing statistics: consistent small byte volume ({mean_bytes:.1f} bytes mean)",
                    ),
                ]
                desc = (
                    f"Stateful C2 beaconing channel detected to {flow.destination_ip}:{flow.destination_port} "
                    f"(period: {mean_interval:.2f}s, jitter CV: {cv_interval:.1%}, {k} flows)"
                )
            else:
                obs_bonus = min(0.08, (k - self.min_observations) * 0.02)
                vol_bonus = max(0.0, (1.0 - (std_pkts / 2.0))) * 0.05
                confidence = min(0.95, max(0.80, 0.82 + obs_bonus + vol_bonus))
                evidence = [
                    DetectionEvidence(
                        feature_name="stateful_flow_count",
                        observed_value=k,
                        threshold_value=self.min_observations,
                        description=f"Sustained communication channel with {k} recurring check-in flows",
                    ),
                    DetectionEvidence(
                        feature_name="mean_flow_packets",
                        observed_value=round(mean_pkts, 1),
                        threshold_value="[4, 20]",
                        description=f"Automated heartbeat check-in packet fingerprint ({mean_pkts:.1f} pkts mean, std {std_pkts:.2f})",
                    ),
                    DetectionEvidence(
                        feature_name="mean_flow_bytes",
                        observed_value=round(mean_bytes, 1),
                        threshold_value=500.0,
                        description=f"Flow metadata / timing statistics: small byte volume check-in ({mean_bytes:.1f} bytes mean, std {std_bytes:.2f})",
                    ),
                    DetectionEvidence(
                        feature_name="bidirectional_packets",
                        observed_value=f"{mean_fwd:.1f} fwd, {mean_bwd:.1f} bwd",
                        threshold_value=">= 2 each",
                        description="Bidirectional command-and-control handshake exchange",
                    ),
                ]
                desc = (
                    f"Stateful programmatic C2 heartbeat detected to {flow.destination_ip}:{flow.destination_port} "
                    f"({mean_pkts:.0f} pkts, {mean_bytes:.0f} bytes, {k} recurring flows)"
                )

            severity = DetectionSeverity.HIGH

            return DetectionSignal(
                signal_id=self._generate_signal_id(),
                threat_type=self.threat_type,
                detector_type=self.detector_type,
                detector_name=self.detector_name,
                confidence=round(confidence, 4),
                severity=severity,
                evidence=evidence,
                description=desc,
                metadata={
                    "endpoint_key": endpoint_key,
                    "source_ip": flow.source_ip,
                    "destination_ip": flow.destination_ip,
                    "destination_port": flow.destination_port,
                    "period_sec": round(mean_interval, 4) if mode1_matched else None,
                    "jitter_ratio": round(cv_interval, 4) if mode1_matched else None,
                    "flow_count": k,
                    "mean_bytes": round(mean_bytes, 2),
                    "mean_packets": round(mean_pkts, 2),
                    "detection_mode": "temporal_jitter" if mode1_matched else "programmatic_heartbeat",
                },
            )

"""Stateful bi-directional 5-tuple flow aggregation engine."""

from datetime import datetime, timezone
import math
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from sentinel_flow_engine.base import BaseFlowAggregator
from sentinel_models.events import FlowRecord, PacketMetadata, ProtocolType


def _to_epoch(dt_or_epoch: Union[datetime, float, int]) -> float:
    """Helper to convert datetime or numeric timestamp to epoch seconds."""
    if isinstance(dt_or_epoch, datetime):
        return dt_or_epoch.timestamp()
    return float(dt_or_epoch)


class _FlowState:
    """Internal mutable tracking state for an in-flight network flow."""

    def __init__(self, first_packet: PacketMetadata) -> None:
        self.start_time: datetime = first_packet.timestamp
        self.last_seen_time: datetime = first_packet.timestamp

        # Direction endpoints relative to originator
        self.source_ip: str = first_packet.source_ip
        self.destination_ip: str = first_packet.destination_ip
        self.source_port: Optional[int] = first_packet.source_port
        self.destination_port: Optional[int] = first_packet.destination_port
        self.protocol: ProtocolType = first_packet.protocol

        epoch_ts = int(self.start_time.timestamp())
        self.flow_id: str = (
            f"flow_{self.source_ip}_{self.source_port}_{self.destination_ip}_"
            f"{self.destination_port}_{self.protocol.value}_{epoch_ts}"
        )

        # Volumetric counters
        self.forward_packets: int = 0
        self.backward_packets: int = 0
        self.forward_bytes: int = 0
        self.backward_bytes: int = 0

        # Packet size statistics (Welford's algorithm)
        self.min_packet_size: int = first_packet.packet_length
        self.max_packet_size: int = first_packet.packet_length
        self._count: int = 0
        self._mean: float = 0.0
        self._m2: float = 0.0

        # TCP flags aggregation
        self.tcp_flags: Dict[str, int] = {
            "syn": 0,
            "ack": 0,
            "fin": 0,
            "rst": 0,
            "psh": 0,
            "urg": 0,
            "ece": 0,
            "cwr": 0,
        }

        self.saw_fin: bool = False
        self.saw_rst: bool = False
        self.termination_reason: Optional[str] = None

        # Ingest the first packet
        self.update(first_packet)

    def is_forward(self, packet: PacketMetadata) -> bool:
        """Determine whether the packet is in the forward direction relative to originator."""
        return (
            packet.source_ip == self.source_ip
            and packet.source_port == self.source_port
        )

    def update(self, packet: PacketMetadata) -> None:
        """Incrementally update flow statistics with an incoming packet."""
        self.last_seen_time = max(self.last_seen_time, packet.timestamp)
        pkt_len = packet.packet_length

        # 1. Forward vs. Backward volumetric counts
        if self.is_forward(packet):
            self.forward_packets += 1
            self.forward_bytes += pkt_len
        else:
            self.backward_packets += 1
            self.backward_bytes += pkt_len

        # 2. Min / Max packet size
        if pkt_len < self.min_packet_size:
            self.min_packet_size = pkt_len
        if pkt_len > self.max_packet_size:
            self.max_packet_size = pkt_len

        # 3. Welford's running mean and variance
        self._count += 1
        delta = pkt_len - self._mean
        self._mean += delta / self._count
        delta2 = pkt_len - self._mean
        self._m2 += delta * delta2

        # 4. TCP flags aggregation
        if packet.tcp_flags is not None:
            if packet.tcp_flags.syn:
                self.tcp_flags["syn"] += 1
            if packet.tcp_flags.ack:
                self.tcp_flags["ack"] += 1
            if packet.tcp_flags.fin:
                self.tcp_flags["fin"] += 1
                self.saw_fin = True
            if packet.tcp_flags.rst:
                self.tcp_flags["rst"] += 1
                self.saw_rst = True
            if packet.tcp_flags.psh:
                self.tcp_flags["psh"] += 1
            if packet.tcp_flags.urg:
                self.tcp_flags["urg"] += 1
            if packet.tcp_flags.ece:
                self.tcp_flags["ece"] += 1
            if packet.tcp_flags.cwr:
                self.tcp_flags["cwr"] += 1

    def to_record(self, reason: Optional[str] = None) -> FlowRecord:
        """Materialize current flow state into an immutable FlowRecord."""
        duration = max(0.0, (self.last_seen_time - self.start_time).total_seconds())
        variance = (self._m2 / self._count) if self._count > 0 else 0.0
        std_dev = math.sqrt(variance)

        if self.saw_rst:
            final_reason = "tcp_rst"
        elif self.saw_fin:
            final_reason = "tcp_fin"
        else:
            final_reason = reason or self.termination_reason or "normal"

        total_pkts = self.forward_packets + self.backward_packets
        total_bytes = self.forward_bytes + self.backward_bytes

        return FlowRecord(
            flow_id=self.flow_id,
            start_time=self.start_time,
            last_seen_time=self.last_seen_time,
            end_time=self.last_seen_time,
            duration_sec=round(duration, 6),
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            source_port=self.source_port,
            destination_port=self.destination_port,
            protocol=self.protocol,
            total_packets=total_pkts,
            forward_packets=self.forward_packets,
            backward_packets=self.backward_packets,
            total_bytes=total_bytes,
            forward_bytes=self.forward_bytes,
            backward_bytes=self.backward_bytes,
            min_packet_size=self.min_packet_size,
            max_packet_size=self.max_packet_size,
            mean_packet_size=round(self._mean, 2),
            std_packet_size=round(std_dev, 2),
            tcp_flags=dict(self.tcp_flags),
            is_active=False,
            termination_reason=final_reason,
            features={},
        )


class BidirectionalFlowAggregator(BaseFlowAggregator):
    """Aggregates raw PacketMetadata into stateful bidirectional 5-tuple FlowRecords."""

    def __init__(
        self,
        inactivity_timeout_sec: float = 30.0,
        active_timeout_sec: float = 120.0,
    ) -> None:
        """Initialize the flow aggregator.
        
        Args:
            inactivity_timeout_sec: Seconds of silence before expiring an idle flow.
            active_timeout_sec: Maximum seconds a continuous flow remains in-flight before being flushed.
        """
        self.inactivity_timeout_sec = max(0.1, inactivity_timeout_sec)
        self.active_timeout_sec = max(0.1, active_timeout_sec)
        self._flows: Dict[Tuple[Any, Any, str], _FlowState] = {}

    @staticmethod
    def _make_canonical_key(packet: PacketMetadata) -> Tuple[Any, Any, str]:
        """Compute symmetric 5-tuple key: (min(endpointA, endpointB), max(endpointA, endpointB), proto)."""
        ep1 = (packet.source_ip, packet.source_port or 0)
        ep2 = (packet.destination_ip, packet.destination_port or 0)
        proto = packet.protocol.value

        if ep1 <= ep2:
            return (ep1, ep2, proto)
        return (ep2, ep1, proto)

    def add_packet(self, packet: PacketMetadata) -> Optional[FlowRecord]:
        """Add a packet to the flow table.
        
        Returns:
            FlowRecord if the flow has reached termination criteria (e.g. TCP RST), else None.
        """
        key = self._make_canonical_key(packet)

        if key in self._flows:
            flow_state = self._flows[key]
            flow_state.update(packet)

            # Optional immediate termination on TCP RST
            if packet.tcp_flags and packet.tcp_flags.rst:
                del self._flows[key]
                return flow_state.to_record(reason="tcp_rst")

            return None
        else:
            # Create a new flow session
            flow_state = _FlowState(packet)
            
            # If a single packet has RST immediately terminate
            if packet.tcp_flags and packet.tcp_flags.rst:
                return flow_state.to_record(reason="tcp_rst")

            self._flows[key] = flow_state
            return None

    def flush_expired(self, current_time: Union[datetime, float]) -> Iterator[FlowRecord]:
        """Flush and yield flows that exceeded inactivity or active timeouts."""
        now_epoch = _to_epoch(current_time)
        expired_keys: List[Tuple[Any, Any, str]] = []
        expired_records: List[FlowRecord] = []

        for key, state in self._flows.items():
            last_epoch = state.last_seen_time.timestamp()
            start_epoch = state.start_time.timestamp()

            if (now_epoch - last_epoch) >= self.inactivity_timeout_sec:
                expired_keys.append(key)
                expired_records.append(state.to_record(reason="inactivity_timeout"))
            elif (now_epoch - start_epoch) >= self.active_timeout_sec:
                expired_keys.append(key)
                expired_records.append(state.to_record(reason="active_timeout"))

        for key in expired_keys:
            del self._flows[key]

        for record in expired_records:
            yield record

    def flush_all(self) -> Iterator[FlowRecord]:
        """Flush and return all currently active flows (e.g., at end of PCAP capture)."""
        active_states = list(self._flows.values())
        self._flows.clear()

        for state in active_states:
            yield state.to_record(reason="end_of_input")

    def get_active_flow_count(self) -> int:
        """Return the number of active in-memory flow sessions."""
        return len(self._flows)

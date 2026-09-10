"""Passive packet ingestion abstractions.

Architectural Invariant:
"The SentinelAI detection pipeline is strictly passive. No component may transmit packets,
perform active probing, complete network handshakes, block traffic, or decrypt application payloads."
"""

from abc import ABC, abstractmethod
from typing import Iterator
from sentinel_models.events import PacketMetadata


class BasePacketSource(ABC):
    """Abstract interface for passive packet capture sources.
    
    Full implementation belongs to Phase 1 (Passive Traffic Ingestion & Flow Engine).
    """

    @abstractmethod
    def stream_packets(self) -> Iterator[PacketMetadata]:
        """Yield parsed PacketMetadata passively without modifying wire traffic."""
        raise NotImplementedError("Passive packet streaming will be implemented in Phase 1.")

    @abstractmethod
    def close(self) -> None:
        """Release underlying socket or PCAP file handles."""
        raise NotImplementedError("Packet source cleanup will be implemented in Phase 1.")

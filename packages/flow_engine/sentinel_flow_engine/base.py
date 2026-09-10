"""Bi-directional flow aggregation engine abstractions.

Responsible for tracking stateful 5-tuple sessions with active/inactive timeouts.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator, Optional, Union
from sentinel_models.events import FlowRecord, PacketMetadata


class BaseFlowAggregator(ABC):
    """Abstract interface for aggregating packet metadata into stateful FlowRecords."""

    @abstractmethod
    def add_packet(self, packet: PacketMetadata) -> Optional[FlowRecord]:
        """Ingest a packet into the flow engine.
        
        Returns:
            Completed FlowRecord if the packet triggered an immediate flow termination (e.g. TCP RST),
            otherwise None.
        """
        raise NotImplementedError

    def process_packet(self, packet: PacketMetadata) -> Optional[FlowRecord]:
        """Alias for add_packet."""
        return self.add_packet(packet)

    @abstractmethod
    def flush_expired(self, current_time: Union[datetime, float]) -> Iterator[FlowRecord]:
        """Flush and yield all flows that have exceeded active or inactive timeouts."""
        raise NotImplementedError

    @abstractmethod
    def flush_all(self) -> Iterator[FlowRecord]:
        """Flush and yield all remaining active flows (e.g. at end of input)."""
        raise NotImplementedError

    @abstractmethod
    def get_active_flow_count(self) -> int:
        """Return the current number of active flows in the state table."""
        raise NotImplementedError

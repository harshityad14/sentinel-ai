"""Bi-directional flow aggregation engine abstractions.

Responsible for tracking stateful 5-tuple sessions with active/inactive timeouts.
Full implementation belongs to Phase 1 (Passive Traffic Ingestion & Flow Engine).
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional
from sentinel_models.events import FlowRecord, PacketMetadata


class BaseFlowAggregator(ABC):
    """Abstract interface for aggregating packet metadata into stateful FlowRecords."""

    @abstractmethod
    def process_packet(self, packet: PacketMetadata) -> Optional[FlowRecord]:
        """Ingest a packet, update active flow table, and return a completed FlowRecord if flushed."""
        raise NotImplementedError("Flow aggregation logic will be implemented in Phase 1.")

    @abstractmethod
    def flush_expired(self, current_time: float) -> Iterator[FlowRecord]:
        """Flush and yield all flows that have exceeded active or inactive timeouts."""
        raise NotImplementedError("Flow expiration logic will be implemented in Phase 1.")

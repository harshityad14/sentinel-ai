"""PCAP and PCAPNG passive packet source implementation."""

import logging
import os
import time
from pathlib import Path
from typing import Iterator, Optional, Union

from scapy.utils import PcapReader

from sentinel_ingestion.base import BasePacketSource
from sentinel_ingestion.parser import PacketParser
from sentinel_models.events import PacketMetadata

logger = logging.getLogger(__name__)


class PcapPacketSource(BasePacketSource):
    """Passively reads packets from standard PCAP / PCAPNG capture files.
    
    Operates strictly read-only and never transmits packets to any network.
    Supports both fast offline batch processing and timestamp-paced replay.
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        replay_mode: bool = False,
        replay_speed: float = 1.0,
    ) -> None:
        """Initialize PCAP packet source.
        
        Args:
            file_path: Path to the .pcap or .pcapng file.
            replay_mode: If True, paces packet emission to simulate real-time stream.
            replay_speed: Speed multiplier for replay mode (e.g. 2.0 = 2x speed).
        """
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")
        if not self.file_path.is_file():
            raise ValueError(f"Path is not a regular file: {self.file_path}")

        self.replay_mode = replay_mode
        self.replay_speed = max(0.001, replay_speed)
        self._reader: Optional[PcapReader] = None
        self._parser = PacketParser()

    def stream_packets(self) -> Iterator[PacketMetadata]:
        """Stream parsed PacketMetadata from the PCAP file.
        
        Yields:
            PacketMetadata instances for each successfully parsed packet.
        """
        try:
            self._reader = PcapReader(str(self.file_path))
        except Exception as err:
            logger.error(f"Failed to open PCAP file {self.file_path}: {err}")
            raise ValueError(f"Invalid or corrupted PCAP file {self.file_path}: {err}") from err

        last_pkt_time: Optional[float] = None

        try:
            for raw_pkt in self._reader:
                # Handle replay timing pacing if enabled
                if self.replay_mode and hasattr(raw_pkt, "time"):
                    curr_time = float(raw_pkt.time)
                    if last_pkt_time is not None:
                        delta = (curr_time - last_pkt_time) / self.replay_speed
                        if 0 < delta < 10.0:  # Cap sleep to prevent excessive pauses on sparse captures
                            time.sleep(delta)
                    last_pkt_time = curr_time

                parsed = self._parser.parse_scapy_packet(raw_pkt)
                if parsed is not None:
                    yield parsed

        finally:
            self.close()

    def close(self) -> None:
        """Release file handles."""
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception as err:
                logger.debug(f"Error closing PcapReader: {err}")
            finally:
                self._reader = None

    def __enter__(self) -> "PcapPacketSource":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

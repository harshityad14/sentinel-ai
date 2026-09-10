"""Passive packet metadata parser.

Translates raw captured packets (e.g. Scapy packet objects) into canonical PacketMetadata.
Operates strictly passively without decrypting application payloads or modifying wire traffic.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.packet import Packet

from sentinel_models.events import PacketMetadata, ProtocolType, TCPFlags

logger = logging.getLogger(__name__)


class PacketParser:
    """Parses raw network packets into normalized PacketMetadata."""

    @staticmethod
    def parse_scapy_packet(packet: Packet) -> Optional[PacketMetadata]:
        """Convert a Scapy packet into a canonical PacketMetadata instance.
        
        Returns None if packet is malformed, truncated, or of an unsupported protocol.
        """
        try:
            # 1. Packet timestamp
            # Scapy packet.time can be float/Decimal epoch timestamp
            pkt_time = getattr(packet, "time", None)
            if pkt_time is not None:
                try:
                    ts = datetime.fromtimestamp(float(pkt_time), tz=timezone.utc)
                except (ValueError, OverflowError):
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            # 2. Wire length
            wire_len = len(packet)

            # 3. L3 Header: IPv4 or IPv6
            source_ip: str
            destination_ip: str

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                source_ip = str(ip_layer.src)
                destination_ip = str(ip_layer.dst)
            elif packet.haslayer(IPv6):
                ip6_layer = packet[IPv6]
                source_ip = str(ip6_layer.src)
                destination_ip = str(ip6_layer.dst)
            else:
                # Non-IP layer (e.g., ARP, STP, raw L2 broadcast) - safely skip
                return None

            # 4. L4 Header: TCP, UDP, ICMP, or other
            source_port: Optional[int] = None
            destination_port: Optional[int] = None
            protocol: ProtocolType = ProtocolType.OTHER
            payload_len: int = 0
            tcp_flags: Optional[TCPFlags] = None

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol = ProtocolType.TCP
                source_port = int(tcp_layer.sport)
                destination_port = int(tcp_layer.dport)
                
                # TCP flags parsing
                # tcp_layer.flags can be evaluated as integer bitmask or FlagValue string
                raw_flags = tcp_layer.flags
                tcp_flags = TCPFlags(
                    syn=bool(raw_flags & 0x02),
                    ack=bool(raw_flags & 0x10),
                    fin=bool(raw_flags & 0x01),
                    rst=bool(raw_flags & 0x04),
                    psh=bool(raw_flags & 0x08),
                    urg=bool(raw_flags & 0x20),
                    ece=bool(raw_flags & 0x40),
                    cwr=bool(raw_flags & 0x80),
                )
                
                if hasattr(tcp_layer, "payload") and tcp_layer.payload:
                    payload_len = len(tcp_layer.payload)

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol = ProtocolType.UDP
                source_port = int(udp_layer.sport)
                destination_port = int(udp_layer.dport)
                
                if hasattr(udp_layer, "payload") and udp_layer.payload:
                    payload_len = len(udp_layer.payload)

            elif packet.haslayer(ICMP) or any(
                packet.haslayer(cls)
                for cls in (ICMPv6Unknown, ICMPv6EchoRequest, ICMPv6EchoReply)
            ):
                protocol = ProtocolType.ICMP
                source_port = None
                destination_port = None
                payload_len = 0

            else:
                protocol = ProtocolType.OTHER
                source_port = None
                destination_port = None

            return PacketMetadata(
                timestamp=ts,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                packet_length=wire_len,
                payload_length=payload_len,
                tcp_flags=tcp_flags,
                dns=None,
                tls=None,
            )

        except Exception as err:
            logger.debug(f"Failed to parse packet safely: {err}")
            return None

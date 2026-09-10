"""Deterministic, repository-safe PCAP fixture generator for unit and integration testing."""

from pathlib import Path
from typing import List, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet
from scapy.utils import wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"


def create_sample_packets(base_time: float = 1700000000.0) -> List[Packet]:
    """Generate a sequence of synthetic test packets covering IPv4 TCP, UDP, and IPv6."""
    packets: List[Packet] = []

    # Flow 1: 192.168.1.50:49152 <-> 10.0.0.5:80 (TCP Handshake + Data + FIN)
    # 1. SYN (Forward)
    p1 = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=49152, dport=80, flags="S", seq=1000)
    p1.time = base_time + 0.000
    packets.append(p1)

    # 2. SYN-ACK (Backward)
    p2 = Ether(src=ETH_DST, dst=ETH_SRC) / IP(src="10.0.0.5", dst="192.168.1.50") / TCP(sport=80, dport=49152, flags="SA", seq=2000, ack=1001)
    p2.time = base_time + 0.010
    packets.append(p2)

    # 3. ACK (Forward)
    p3 = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=2001)
    p3.time = base_time + 0.020
    packets.append(p3)

    # 4. HTTP Request Data (Forward, 120 bytes payload)
    p4 = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=2001) / (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"X" * 70)
    p4.time = base_time + 0.050
    packets.append(p4)

    # 5. HTTP Response Data (Backward, 300 bytes payload)
    p5 = Ether(src=ETH_DST, dst=ETH_SRC) / IP(src="10.0.0.5", dst="192.168.1.50") / TCP(sport=80, dport=49152, flags="PA", seq=2001, ack=1121) / (b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n" + b"Y" * 250)
    p5.time = base_time + 0.080
    packets.append(p5)

    # 6. FIN (Forward)
    p6 = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=49152, dport=80, flags="FA", seq=1121, ack=2301)
    p6.time = base_time + 0.100
    packets.append(p6)

    # Flow 2: 192.168.1.50:53535 <-> 8.8.8.8:53 (UDP DNS Query & Response)
    # Forward DNS Query
    p7 = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53535, dport=53) / (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
    p7.time = base_time + 0.200
    packets.append(p7)

    # Backward DNS Response
    p8 = Ether(src=ETH_DST, dst=ETH_SRC) / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=53535) / (b"\xaa\xbb\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22")
    p8.time = base_time + 0.220
    packets.append(p8)

    # Flow 3: IPv6 TCP: 2001:db8::1:9000 <-> 2001:db8::2:443
    p9 = Ether(src=ETH_SRC, dst=ETH_DST) / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=9000, dport=443, flags="S", seq=500)
    p9.time = base_time + 0.300
    packets.append(p9)

    # Non-IP packet (ARP) - should be skipped safely by parser
    p10 = Ether(src=ETH_SRC, dst=ETH_DST) / ARP(psrc="192.168.1.1", pdst="192.168.1.50")
    p10.time = base_time + 0.400
    packets.append(p10)

    return packets


def write_test_pcap(file_path: Path, packets: Optional[List[Packet]] = None) -> Path:
    """Write synthetic packets to a temporary or fixture PCAP file."""
    if packets is None:
        packets = create_sample_packets()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(file_path), packets)
    return file_path

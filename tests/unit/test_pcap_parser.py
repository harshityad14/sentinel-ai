"""Unit tests for PacketParser and PcapPacketSource."""

import tempfile
import unittest
from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

from sentinel_ingestion.parser import PacketParser
from sentinel_ingestion.pcap_source import PcapPacketSource
from sentinel_models.events import ProtocolType
from tests.fixtures.pcap_generator import write_test_pcap, create_sample_packets, ETH_SRC, ETH_DST


class TestPacketParser(unittest.TestCase):
    def setUp(self):
        self.parser = PacketParser()

    def test_ipv4_tcp_packet(self):
        pkt = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=50000, dport=80, flags="S")
        pkt.time = 1700000000.5
        metadata = self.parser.parse_scapy_packet(pkt)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.source_ip, "192.168.1.10")
        self.assertEqual(metadata.destination_ip, "10.0.0.1")
        self.assertEqual(metadata.source_port, 50000)
        self.assertEqual(metadata.destination_port, 80)
        self.assertEqual(metadata.protocol, ProtocolType.TCP)
        self.assertTrue(metadata.tcp_flags.syn)
        self.assertFalse(metadata.tcp_flags.ack)
        self.assertGreater(metadata.packet_length, 0)

    def test_ipv4_udp_packet(self):
        pkt = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=5353, dport=53) / b"ping"
        pkt.time = 1700000001.0
        metadata = self.parser.parse_scapy_packet(pkt)

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.source_ip, "192.168.1.20")
        self.assertEqual(metadata.destination_ip, "8.8.8.8")
        self.assertEqual(metadata.source_port, 5353)
        self.assertEqual(metadata.destination_port, 53)
        self.assertEqual(metadata.protocol, ProtocolType.UDP)
        self.assertIsNone(metadata.tcp_flags)
        self.assertEqual(metadata.payload_length, 4)

    def test_ipv6_packet(self):
        pkt = Ether(src=ETH_SRC, dst=ETH_DST) / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=9000, dport=443, flags="PA")
        metadata = self.parser.parse_scapy_packet(pkt)

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.source_ip, "2001:db8::1")
        self.assertEqual(metadata.destination_ip, "2001:db8::2")
        self.assertEqual(metadata.protocol, ProtocolType.TCP)
        self.assertTrue(metadata.tcp_flags.psh)
        self.assertTrue(metadata.tcp_flags.ack)

    def test_tcp_flags_decoding(self):
        pkt = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1111, dport=2222, flags="FSRPAUEC")
        metadata = self.parser.parse_scapy_packet(pkt)
        
        self.assertIsNotNone(metadata)
        flags = metadata.tcp_flags
        self.assertTrue(flags.fin)
        self.assertTrue(flags.syn)
        self.assertTrue(flags.rst)
        self.assertTrue(flags.psh)
        self.assertTrue(flags.ack)
        self.assertTrue(flags.urg)
        self.assertTrue(flags.ece)
        self.assertTrue(flags.cwr)

    def test_non_ip_packet_skipped(self):
        pkt = Ether(src=ETH_SRC, dst=ETH_DST) / ARP(psrc="192.168.1.1", pdst="192.168.1.2")
        metadata = self.parser.parse_scapy_packet(pkt)
        self.assertIsNone(metadata)


class TestPcapPacketSource(unittest.TestCase):
    def test_read_pcap_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            write_test_pcap(tmp_path)
            with PcapPacketSource(tmp_path) as source:
                packets = list(source.stream_packets())
            
            # The sample fixture contains 10 packets (9 IP, 1 ARP)
            # The 9 IP packets should be parsed successfully
            self.assertEqual(len(packets), 9)
            self.assertEqual(packets[0].protocol, ProtocolType.TCP)
            self.assertEqual(packets[0].source_port, 49152)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_missing_file_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            PcapPacketSource("non_existent_file.pcap")


if __name__ == "__main__":
    unittest.main()

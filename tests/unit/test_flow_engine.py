"""Unit tests for BidirectionalFlowAggregator covering all lifecycle and statistical requirements."""

import unittest
from datetime import datetime, timezone

from sentinel_flow_engine.aggregator import BidirectionalFlowAggregator
from sentinel_models.events import PacketMetadata, ProtocolType, TCPFlags


def _make_pkt(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    sport=50000,
    dport=80,
    proto=ProtocolType.TCP,
    length=100,
    timestamp=1700000000.0,
    flags=None,
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc),
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=sport,
        destination_port=dport,
        protocol=proto,
        packet_length=length,
        payload_length=max(0, length - 40),
        tcp_flags=flags or TCPFlags(),
    )


class TestFlowEngine(unittest.TestCase):
    def setUp(self):
        self.aggregator = BidirectionalFlowAggregator(
            inactivity_timeout_sec=10.0,
            active_timeout_sec=60.0,
        )

    def test_creates_new_flow(self):
        pkt = _make_pkt()
        self.aggregator.add_packet(pkt)
        self.assertEqual(self.aggregator.get_active_flow_count(), 1)

    def test_aggregates_packets(self):
        p1 = _make_pkt(timestamp=1700000000.0, length=100)
        p2 = _make_pkt(timestamp=1700000001.0, length=200)
        self.aggregator.add_packet(p1)
        self.aggregator.add_packet(p2)
        
        self.assertEqual(self.aggregator.get_active_flow_count(), 1)
        flows = list(self.aggregator.flush_all())
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.total_packets, 2)
        self.assertEqual(flow.forward_packets, 2)
        self.assertEqual(flow.backward_packets, 0)
        self.assertEqual(flow.total_bytes, 300)

    def test_reverse_direction_packets_map_to_same_flow(self):
        # Forward: A:50000 -> B:80
        fwd_pkt = _make_pkt(src_ip="192.168.1.10", dst_ip="10.0.0.1", sport=50000, dport=80, length=150)
        # Backward: B:80 -> A:50000
        rev_pkt = _make_pkt(src_ip="10.0.0.1", dst_ip="192.168.1.10", sport=80, dport=50000, length=250)

        self.aggregator.add_packet(fwd_pkt)
        self.aggregator.add_packet(rev_pkt)

        self.assertEqual(self.aggregator.get_active_flow_count(), 1)
        flows = list(self.aggregator.flush_all())
        self.assertEqual(len(flows), 1)
        flow = flows[0]

        # Verify endpoints match originator
        self.assertEqual(flow.source_ip, "192.168.1.10")
        self.assertEqual(flow.destination_ip, "10.0.0.1")
        self.assertEqual(flow.source_port, 50000)
        self.assertEqual(flow.destination_port, 80)
        self.assertEqual(flow.forward_packets, 1)
        self.assertEqual(flow.backward_packets, 1)
        self.assertEqual(flow.forward_bytes, 150)
        self.assertEqual(flow.backward_bytes, 250)
        self.assertEqual(flow.total_bytes, 400)

    def test_multiple_independent_flows_remain_independent(self):
        p1 = _make_pkt(sport=50001, dport=80)
        p2 = _make_pkt(sport=50002, dport=80)
        p3 = _make_pkt(sport=50001, dport=443)

        self.aggregator.add_packet(p1)
        self.aggregator.add_packet(p2)
        self.aggregator.add_packet(p3)

        self.assertEqual(self.aggregator.get_active_flow_count(), 3)
        flows = list(self.aggregator.flush_all())
        self.assertEqual(len(flows), 3)

    def test_duration_calculation(self):
        p1 = _make_pkt(timestamp=1700000000.0)
        p2 = _make_pkt(timestamp=1700000005.5)

        self.aggregator.add_packet(p1)
        self.aggregator.add_packet(p2)

        flow = list(self.aggregator.flush_all())[0]
        self.assertAlmostEqual(flow.duration_sec, 5.5, places=3)

    def test_packet_size_statistics(self):
        # Packets of sizes: 100, 200, 300
        # Min = 100, Max = 300, Mean = 200.0, Std = sqrt(((100-200)^2 + (200-200)^2 + (300-200)^2)/3) = sqrt(20000/3) = 81.65
        for sz in [100, 200, 300]:
            self.aggregator.add_packet(_make_pkt(length=sz))

        flow = list(self.aggregator.flush_all())[0]
        self.assertEqual(flow.min_packet_size, 100)
        self.assertEqual(flow.max_packet_size, 300)
        self.assertEqual(flow.mean_packet_size, 200.0)
        self.assertAlmostEqual(flow.std_packet_size, 81.65, places=1)

    def test_tcp_flag_aggregation(self):
        p1 = _make_pkt(flags=TCPFlags(syn=True))
        p2 = _make_pkt(flags=TCPFlags(syn=True, ack=True))
        p3 = _make_pkt(flags=TCPFlags(ack=True))
        p4 = _make_pkt(flags=TCPFlags(fin=True, ack=True))

        for p in [p1, p2, p3, p4]:
            self.aggregator.add_packet(p)

        flow = list(self.aggregator.flush_all())[0]
        self.assertEqual(flow.tcp_flags["syn"], 2)
        self.assertEqual(flow.tcp_flags["ack"], 3)
        self.assertEqual(flow.tcp_flags["fin"], 1)
        self.assertEqual(flow.tcp_flags["rst"], 0)
        self.assertEqual(flow.termination_reason, "tcp_fin")

    def test_inactivity_timeout_flush(self):
        p1 = _make_pkt(timestamp=1700000000.0)
        self.aggregator.add_packet(p1)
        self.assertEqual(self.aggregator.get_active_flow_count(), 1)

        # 5 seconds later: not yet expired (timeout is 10.0s)
        expired = list(self.aggregator.flush_expired(1700000005.0))
        self.assertEqual(len(expired), 0)
        self.assertEqual(self.aggregator.get_active_flow_count(), 1)

        # 11 seconds later: expired
        expired = list(self.aggregator.flush_expired(1700000011.0))
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].termination_reason, "inactivity_timeout")
        self.assertEqual(self.aggregator.get_active_flow_count(), 0)

    def test_explicit_flush_all(self):
        self.aggregator.add_packet(_make_pkt(sport=1001))
        self.aggregator.add_packet(_make_pkt(sport=1002))
        self.assertEqual(self.aggregator.get_active_flow_count(), 2)

        flows = list(self.aggregator.flush_all())
        self.assertEqual(len(flows), 2)
        self.assertEqual(self.aggregator.get_active_flow_count(), 0)
        self.assertEqual(flows[0].termination_reason, "end_of_input")

    def test_empty_input(self):
        flows = list(self.aggregator.flush_all())
        self.assertEqual(len(flows), 0)
        self.assertEqual(self.aggregator.get_active_flow_count(), 0)


if __name__ == "__main__":
    unittest.main()

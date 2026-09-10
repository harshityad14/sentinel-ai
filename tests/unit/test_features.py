"""Comprehensive unit tests for SentinelAI Phase 2 Feature Engineering."""

from datetime import datetime, timezone
import json
import unittest

from sentinel_features.dns import DNSFeatureExtractor
from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_features.network import NetworkFeatureExtractor
from sentinel_features.registry import FeatureDataType, FeatureDefinition, FeatureRegistry, FeatureStatus
from sentinel_features.statistical import (
    rate,
    ratio,
    safe_div,
    shannon_entropy,
    summary_statistics,
)
from sentinel_features.tcp import TCPFeatureExtractor
from sentinel_features.tls import TLSFeatureExtractor
from sentinel_features.timing import TimingFeatureExtractor
from sentinel_models.events import DNSMetadata, FlowRecord, ProtocolType, TLSMetadata
from sentinel_models.features import FeatureVector


def _build_test_flow(
    flow_id: str = "test_flow_01",
    duration: float = 10.0,
    total_pkts: int = 20,
    fwd_pkts: int = 12,
    bwd_pkts: int = 8,
    fwd_bytes: int = 6000,
    bwd_bytes: int = 4000,
    proto: ProtocolType = ProtocolType.TCP,
    tcp_flags=None,
    dns_ctx=None,
    tls_ctx=None,
) -> FlowRecord:
    now = datetime.now(timezone.utc)
    return FlowRecord(
        flow_id=flow_id,
        start_time=now,
        end_time=now,
        duration_sec=duration,
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        source_port=49152,
        destination_port=443,
        protocol=proto,
        total_packets=total_pkts,
        forward_packets=fwd_pkts,
        backward_packets=bwd_pkts,
        total_bytes=fwd_bytes + bwd_bytes,
        forward_bytes=fwd_bytes,
        backward_bytes=bwd_bytes,
        min_packet_size=60,
        max_packet_size=1500,
        mean_packet_size=500.0,
        std_packet_size=250.0,
        tcp_flags=tcp_flags or {},
        dns_context=dns_ctx,
        tls_context=tls_ctx,
    )


class TestStatisticalUtilities(unittest.TestCase):
    def test_safe_div(self):
        self.assertEqual(safe_div(10, 2), 5.0)
        self.assertEqual(safe_div(10, 0), 0.0)
        self.assertEqual(safe_div(10, 0, default=1.0), 1.0)
        self.assertEqual(safe_div(float("nan"), 5), 0.0)
        self.assertEqual(safe_div(5, float("nan")), 0.0)

    def test_shannon_entropy(self):
        # Empty string
        self.assertEqual(shannon_entropy(""), 0.0)
        # Monotonous string
        self.assertEqual(shannon_entropy("aaaaaaa"), 0.0)
        # Typical natural language domain
        ent_normal = shannon_entropy("google.com")
        self.assertGreater(ent_normal, 2.0)
        self.assertLess(ent_normal, 3.5)
        # High-entropy random DGA domain
        ent_dga = shannon_entropy("xk89qz4w7pv3mc1b0y.biz")
        self.assertGreater(ent_dga, 3.8)
        # Unicode string handling without error
        self.assertGreaterEqual(shannon_entropy("münchen.de"), 0.0)

    def test_summary_statistics(self):
        # Empty sequence
        self.assertEqual(summary_statistics([]), (0.0, 0.0, 0.0, 0.0))
        # Single element
        self.assertEqual(summary_statistics([42.0]), (42.0, 42.0, 42.0, 0.0))
        # Multi-element sequence
        min_v, max_v, mean_v, std_v = summary_statistics([10.0, 20.0, 30.0])
        self.assertEqual(min_v, 10.0)
        self.assertEqual(max_v, 30.0)
        self.assertEqual(mean_v, 20.0)
        self.assertAlmostEqual(std_v, 8.165, places=2)


class TestNetworkFeatures(unittest.TestCase):
    def test_standard_rates_and_ratios(self):
        flow = _build_test_flow(
            duration=5.0,
            total_pkts=50,
            fwd_pkts=30,
            bwd_pkts=20,
            fwd_bytes=15000,
            bwd_bytes=10000,
        )
        feats = NetworkFeatureExtractor.extract(flow)

        self.assertEqual(feats.packets_per_second, 10.0)
        self.assertEqual(feats.bytes_per_second, 5000.0)
        self.assertEqual(feats.forward_packets_per_second, 6.0)
        self.assertEqual(feats.backward_packets_per_second, 4.0)
        self.assertEqual(feats.forward_backward_packet_ratio, 1.5)
        self.assertEqual(feats.forward_backward_byte_ratio, 1.5)
        self.assertEqual(feats.byte_asymmetry_ratio, 0.6)
        self.assertEqual(feats.mean_packet_size, 500.0)

    def test_zero_duration_edge_case(self):
        flow = _build_test_flow(duration=0.0, total_pkts=1, fwd_pkts=1, bwd_pkts=0, fwd_bytes=100, bwd_bytes=0)
        feats = NetworkFeatureExtractor.extract(flow)

        self.assertEqual(feats.duration_sec, 0.0)
        self.assertEqual(feats.packets_per_second, 0.0)
        self.assertEqual(feats.bytes_per_second, 0.0)
        self.assertEqual(feats.forward_backward_packet_ratio, 0.0)
        self.assertEqual(feats.forward_backward_byte_ratio, 0.0)
        self.assertEqual(feats.byte_asymmetry_ratio, 1.0)

    def test_zero_bytes_and_packets(self):
        flow = _build_test_flow(duration=1.0, total_pkts=0, fwd_pkts=0, bwd_pkts=0, fwd_bytes=0, bwd_bytes=0)
        feats = NetworkFeatureExtractor.extract(flow)

        self.assertEqual(feats.total_packets, 0)
        self.assertEqual(feats.total_bytes, 0)
        self.assertEqual(feats.packets_per_second, 0.0)
        self.assertEqual(feats.bytes_per_second, 0.0)
        self.assertEqual(feats.byte_asymmetry_ratio, 0.5)


class TestTCPFeatures(unittest.TestCase):
    def test_tcp_flag_metrics(self):
        flags = {"syn": 2, "ack": 10, "fin": 1, "rst": 0, "psh": 4, "urg": 0, "ece": 0, "cwr": 0}
        flow = _build_test_flow(proto=ProtocolType.TCP, tcp_flags=flags, total_pkts=12)
        feats = TCPFeatureExtractor.extract(flow)

        self.assertIsNotNone(feats)
        self.assertEqual(feats.syn_count, 2)
        self.assertEqual(feats.ack_count, 10)
        self.assertEqual(feats.syn_ack_ratio, 0.2)
        self.assertEqual(feats.rst_ratio, 0.0)
        self.assertAlmostEqual(feats.fin_ratio, round(1 / 12, 4))

    def test_non_tcp_flow_returns_none(self):
        flow = _build_test_flow(proto=ProtocolType.UDP, tcp_flags={})
        feats = TCPFeatureExtractor.extract(flow)
        self.assertIsNone(feats)

    def test_tcp_without_flags_returns_none(self):
        flow = _build_test_flow(proto=ProtocolType.TCP, tcp_flags={})
        feats = TCPFeatureExtractor.extract(flow)
        self.assertIsNone(feats)


class TestTimingFeatures(unittest.TestCase):
    def test_aggregate_timing(self):
        flow = _build_test_flow(duration=10.0, total_pkts=11)
        feats = TimingFeatureExtractor.extract(flow)

        self.assertEqual(feats.mean_inter_arrival_sec, 1.0)
        self.assertIsNone(feats.min_inter_arrival_sec)
        self.assertIsNone(feats.inter_arrival_std_sec)

    def test_sequence_timing(self):
        flow = _build_test_flow(duration=4.0, total_pkts=5)
        timestamps = [100.0, 101.0, 102.0, 103.0, 104.0]
        feats = TimingFeatureExtractor.extract(flow, packet_timestamps=timestamps)

        self.assertEqual(feats.mean_inter_arrival_sec, 1.0)
        self.assertEqual(feats.min_inter_arrival_sec, 1.0)
        self.assertEqual(feats.max_inter_arrival_sec, 1.0)
        self.assertEqual(feats.inter_arrival_std_sec, 0.0)
        self.assertEqual(feats.jitter_ratio, 0.0)

    def test_single_packet_timing(self):
        flow = _build_test_flow(duration=0.0, total_pkts=1)
        feats = TimingFeatureExtractor.extract(flow, packet_timestamps=[100.0])
        self.assertEqual(feats.mean_inter_arrival_sec, 0.0)
        self.assertIsNone(feats.min_inter_arrival_sec)


class TestDNSFeatures(unittest.TestCase):
    def test_normal_domain_features(self):
        dns = DNSMetadata(
            query_name="mail.google.com",
            query_type="A",
            response_code="NOERROR",
        )
        feats = DNSFeatureExtractor.extract(dns)

        self.assertIsNotNone(feats)
        self.assertEqual(feats.query_length, 15)
        self.assertEqual(feats.label_count, 3)
        self.assertEqual(feats.subdomain_depth, 1)
        self.assertGreater(feats.shannon_entropy, 0.0)
        self.assertEqual(feats.digit_ratio, 0.0)
        self.assertFalse(feats.is_nxdomain)

    def test_dga_and_nxdomain(self):
        dns = DNSMetadata(
            query_name="xk98172qz491.biz",
            query_type="A",
            response_code="NXDOMAIN",
        )
        feats = DNSFeatureExtractor.extract(dns)

        self.assertIsNotNone(feats)
        self.assertTrue(feats.is_nxdomain)
        self.assertGreater(feats.digit_ratio, 0.2)
        self.assertGreater(feats.shannon_entropy, 3.5)

    def test_empty_or_none_dns(self):
        self.assertIsNone(DNSFeatureExtractor.extract(None))
        dns_empty = DNSMetadata(query_name="", query_type="A")
        self.assertIsNone(DNSFeatureExtractor.extract(dns_empty))


class TestTLSFeatures(unittest.TestCase):
    def test_tls_metadata_extraction(self):
        tls = TLSMetadata(
            sni="secure.bank.com",
            version="TLS 1.3",
            cipher_suites=["0x1301", "0x1302"],
            ja3="771,4865-4866,43-51,29-23,0",
            ja4="t13d1516h2_8daaf6152771_018397120387",
        )
        feats = TLSFeatureExtractor.extract(tls)

        self.assertIsNotNone(feats)
        self.assertEqual(feats.tls_version, "TLS 1.3")
        self.assertTrue(feats.sni_present)
        self.assertEqual(feats.cipher_suite_count, 2)
        self.assertTrue(feats.ja3_present)
        self.assertTrue(feats.ja4_present)
        self.assertEqual(feats.ja3_hash, "771,4865-4866,43-51,29-23,0")

    def test_none_tls(self):
        self.assertIsNone(TLSFeatureExtractor.extract(None))


class TestFeatureRegistry(unittest.TestCase):
    def test_registry_lookup_and_filtering(self):
        reg = FeatureRegistry()
        feat = reg.get("duration_sec", version="1.0")
        self.assertIsNotNone(feat)
        self.assertEqual(feat.category, "network")
        self.assertEqual(feat.data_type, FeatureDataType.FLOAT)

        net_feats = reg.list_features(category="network")
        self.assertGreater(len(net_feats), 10)

        planned_feats = reg.list_features(status=FeatureStatus.PLANNED)
        self.assertEqual(len(planned_feats), 1)
        self.assertEqual(planned_feats[0].name, "splt_sequence")

    def test_duplicate_registration_raises(self):
        reg = FeatureRegistry()
        dup = FeatureDefinition(
            name="duration_sec",
            description="dup",
            data_type=FeatureDataType.FLOAT,
            category="network",
            version="1.0",
        )
        with self.assertRaises(ValueError):
            reg.register(dup)


class TestUnifiedFeatureExtractor(unittest.TestCase):
    def test_full_extraction_and_json_serialization(self):
        dns = DNSMetadata(query_name="api.github.com", query_type="A", response_code="NOERROR")
        tls = TLSMetadata(sni="api.github.com", version="TLS 1.3", ja3="abc123ja3hash")
        flags = {"syn": 1, "ack": 1, "fin": 1, "rst": 0, "psh": 1, "urg": 0, "ece": 0, "cwr": 0}
        
        flow = _build_test_flow(
            proto=ProtocolType.TCP,
            tcp_flags=flags,
            dns_ctx=dns,
            tls_ctx=tls,
            duration=2.5,
            total_pkts=10,
        )

        extractor = UnifiedFeatureExtractor()
        vec = extractor.extract(flow, packet_timestamps=[10.0, 10.5, 11.0, 12.0, 12.5])

        self.assertIsInstance(vec, FeatureVector)
        self.assertEqual(vec.flow_id, flow.flow_id)
        self.assertEqual(vec.feature_version, "1.0")
        self.assertIsNotNone(vec.network)
        self.assertIsNotNone(vec.tcp)
        self.assertIsNotNone(vec.timing)
        self.assertIsNotNone(vec.dns)
        self.assertIsNotNone(vec.tls)

        # Flat dictionary extraction
        flat = vec.to_flat_dict()
        self.assertIn("net_duration_sec", flat)
        self.assertIn("tcp_syn_count", flat)
        self.assertIn("time_jitter_ratio", flat)
        self.assertIn("dns_shannon_entropy", flat)
        self.assertIn("tls_ja3_present", flat)
        self.assertEqual(flat["tls_ja3_present"], True)

        # JSON serialization
        json_str = vec.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["flow_id"], flow.flow_id)
        self.assertEqual(parsed["network"]["total_packets"], 10)

    def test_non_tcp_missing_dns_tls_flattens_with_explicit_none(self):
        flow = _build_test_flow(proto=ProtocolType.UDP, tcp_flags={}, dns_ctx=None, tls_ctx=None)
        extractor = UnifiedFeatureExtractor()
        vec = extractor.extract(flow)

        self.assertIsNone(vec.tcp)
        self.assertIsNone(vec.dns)
        self.assertIsNone(vec.tls)

        flat = vec.to_flat_dict()
        self.assertIsNone(flat["tcp_syn_count"])
        self.assertIsNone(flat["dns_shannon_entropy"])
        self.assertIsNone(flat["tls_sni_present"])


if __name__ == "__main__":
    unittest.main()

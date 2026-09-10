"""Comprehensive deterministic unit tests for SentinelAI Phase 3 Hybrid Threat Detection Engine."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from sentinel_detection.base import BaseDetector
from sentinel_detection.correlation.ensemble import EnsembleCorrelationEngine
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.ml.trainer import (
    CANONICAL_ML_FEATURES,
    create_deterministic_baseline_model,
    save_model_artifacts,
)
from sentinel_detection.pipeline import DetectionPipeline, create_default_detection_pipeline
from sentinel_detection.rules import (
    C2BeaconingRuleDetector,
    DataExfiltrationRuleDetector,
    DNSDGARuleDetector,
    DNSTunnelingRuleDetector,
    PortScanRuleDetector,
    SuspiciousTLSRuleDetector,
    SYNFloodRuleDetector,
    UDPFloodRuleDetector,
)
from sentinel_detection.scoring.severity_policy import BASELINE_SEVERITY, evaluate_severity
from sentinel_detection.statistical.anomaly_detector import StatisticalAnomalyDetector
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionResult,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import (
    DNSFeatures,
    FeatureVector,
    NetworkFeatures,
    TCPFeatures,
    TimingFeatures,
    TLSFeatures,
)


def make_dummy_flow(
    protocol: ProtocolType = ProtocolType.TCP,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 49152,
    dst_port: int = 80,
    total_packets: int = 10,
    total_bytes: int = 1000,
) -> FlowRecord:
    """Helper creating a valid FlowRecord fixture."""
    now = datetime.now(timezone.utc)
    return FlowRecord(
        flow_id="test_flow_001",
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        start_time=now,
        last_seen=now,
        total_packets=total_packets,
        total_bytes=total_bytes,
    )


def make_dummy_features(
    flow_id: str = "test_flow_001",
    duration: float = 1.0,
    total_packets: int = 10,
    outbound_packets: int = 5,
    inbound_packets: int = 5,
    total_bytes: int = 1000,
    outbound_bytes: int = 500,
    inbound_bytes: int = 500,
    pps: float = 10.0,
    bps: float = 1000.0,
    syn_count: int = 1,
    ack_count: int = 1,
    rst_count: int = 0,
    dns: bool = False,
    query: str = "example.com",
    entropy: float = 2.5,
    tls: bool = False,
    tls_version: str = "TLS 1.3",
    sni: bool = True,
    cipher_count: int = 16,
    jitter: float = 0.5,
) -> FeatureVector:
    fwd_pkts = outbound_packets
    bwd_pkts = inbound_packets
    fwd_bytes = outbound_bytes
    bwd_bytes = inbound_bytes
    asym_ratio = float(fwd_bytes) / max(1.0, float(fwd_bytes + bwd_bytes))

    tcp_feat = TCPFeatures(
        syn_count=syn_count,
        ack_count=ack_count,
        fin_count=0,
        rst_count=rst_count,
        psh_count=0,
        urg_count=0,
        ece_count=0,
        cwr_count=0,
        syn_ack_ratio=float(syn_count) / max(1.0, float(ack_count)),
        rst_ratio=float(rst_count) / max(1.0, float(total_packets)),
        fin_ratio=0.0,
    )

    net_feat = NetworkFeatures(
        duration_sec=duration,
        total_packets=total_packets,
        total_bytes=total_bytes,
        forward_packets=fwd_pkts,
        backward_packets=bwd_pkts,
        forward_bytes=fwd_bytes,
        backward_bytes=bwd_bytes,
        packets_per_second=pps,
        bytes_per_second=bps,
        forward_packets_per_second=pps * 0.5,
        backward_packets_per_second=pps * 0.5,
        forward_backward_packet_ratio=float(fwd_pkts) / max(1.0, float(bwd_pkts)),
        forward_backward_byte_ratio=float(fwd_bytes) / max(1.0, float(bwd_bytes)),
        byte_asymmetry_ratio=asym_ratio,
        mean_packet_size=float(total_bytes) / max(1, total_packets),
        min_packet_size=40,
        max_packet_size=1500,
        packet_size_std=10.0,
    )

    timing_feat = TimingFeatures(
        mean_inter_arrival_sec=0.1,
        min_inter_arrival_sec=0.01,
        max_inter_arrival_sec=0.2,
        inter_arrival_std_sec=0.05,
        jitter_ratio=jitter,
        burst_count=1,
    )

    dns_feat = None
    if dns:
        dns_feat = DNSFeatures(
            query_length=len(query),
            subdomain_depth=query.count("."),
            shannon_entropy=entropy,
            digit_ratio=0.1,
            alphabetic_ratio=0.8,
            unique_char_ratio=0.7,
            label_count=query.count(".") + 1,
            is_nxdomain=False,
        )

    tls_feat = None
    if tls:
        tls_feat = TLSFeatures(
            tls_version=tls_version,
            sni_present=sni,
            cipher_suite_count=cipher_count,
            ja3_present=True,
            ja3_hash="ada70206e40642a3e4461f35503241d5",
            ja4_present=True,
            ja4_hash="t13d1516h2_8daaf6152771_b186095e22b6",
        )

    return FeatureVector(
        flow_id=flow_id,
        network=net_feat,
        tcp=tcp_feat,
        timing=timing_feat,
        dns=dns_feat,
        tls=tls_feat,
    )


class TestSYNFloodDetector(unittest.TestCase):
    """Test SYN flood volumetric rule detector."""

    def setUp(self) -> None:
        self.detector = SYNFloodRuleDetector(min_syn_count=20, min_syn_ack_ratio=5.0, min_pps=30.0)

    def test_obvious_positive(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        features = make_dummy_features(syn_count=150, ack_count=2, pps=50.0, total_packets=152)
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.SYN_FLOOD)
        self.assertEqual(signal.detector_type, DetectorType.RULE)
        self.assertGreaterEqual(signal.confidence, 0.85)
        self.assertEqual(signal.severity, DetectionSeverity.CRITICAL)
        self.assertTrue(len(signal.evidence) >= 3)
        self.assertEqual(signal.evidence[0].feature_name, "tcp_syn_count")
        self.assertEqual(signal.evidence[0].observed_value, 150)

    def test_normal_tcp(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        features = make_dummy_features(syn_count=1, ack_count=10, pps=5.0)
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_borderline_cases(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        # syn_count just below threshold
        feat1 = make_dummy_features(syn_count=19, ack_count=1, pps=50.0)
        self.assertIsNone(self.detector.detect(flow, feat1))

        # syn_ack_ratio just below threshold
        feat2 = make_dummy_features(syn_count=25, ack_count=6, pps=50.0)  # ratio = 4.16 < 5.0
        self.assertIsNone(self.detector.detect(flow, feat2))

        # pps below threshold
        feat3 = make_dummy_features(syn_count=25, ack_count=1, pps=20.0)
        self.assertIsNone(self.detector.detect(flow, feat3))

    def test_configurable_thresholds(self) -> None:
        custom_detector = SYNFloodRuleDetector(min_syn_count=10, min_syn_ack_ratio=2.0, min_pps=10.0)
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        features = make_dummy_features(syn_count=12, ack_count=4, pps=15.0)
        signal = custom_detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.SYN_FLOOD)


class TestUDPFloodDetector(unittest.TestCase):
    """Test UDP flood rule detector."""

    def setUp(self) -> None:
        self.detector = UDPFloodRuleDetector(min_pps=50.0, min_bps=20000.0, min_packets=100)

    def test_obvious_positive(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP)
        features = make_dummy_features(pps=100.0, bps=50000.0, total_packets=500)
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.UDP_FLOOD)
        self.assertGreaterEqual(signal.confidence, 0.80)

    def test_normal_udp(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP)
        features = make_dummy_features(pps=2.0, bps=500.0, total_packets=4)
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_borderline_udp(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP)
        # packets below min_packets
        features = make_dummy_features(pps=60.0, bps=25000.0, total_packets=90)
        self.assertIsNone(self.detector.detect(flow, features))


class TestPortScanDetector(unittest.TestCase):
    """Test Port scan rule detector with correlated host context."""

    def setUp(self) -> None:
        self.detector = PortScanRuleDetector(min_scanned_ports=15, max_probe_duration_sec=2.0)

    def test_insufficient_evidence_single_flow_alone(self) -> None:
        # A single flow without multi-flow context MUST NOT trigger port scan
        flow = make_dummy_flow()
        features = make_dummy_features(rst_count=1, total_packets=2, duration=0.01)
        signal = self.detector.detect(flow, features, context=None)
        self.assertIsNone(signal)

    def test_correlated_scan_pattern(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features(rst_count=2, total_packets=2, duration=0.02)
        # Context provided by session / host correlation
        context = {
            "scanned_ports_count": 25,
            "scanned_ports": [21, 22, 23, 25, 80, 443, 8080],
            "probe_duration_sec": 0.02,
        }
        signal = self.detector.detect(flow, features, context=context)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.PORT_SCAN)
        self.assertEqual(signal.detector_type, DetectorType.RULE)
        self.assertTrue(any(ev.feature_name == "scanned_ports_count" for ev in signal.evidence))

    def test_normal_multi_port_activity(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features(rst_count=0, total_packets=50, duration=10.0)
        context = {"scanned_ports_count": 3}
        signal = self.detector.detect(flow, features, context=context)
        self.assertIsNone(signal)


class TestC2BeaconingDetector(unittest.TestCase):
    """Test C2 beaconing periodicity and jitter rule detector."""

    def setUp(self) -> None:
        self.detector = C2BeaconingRuleDetector(max_jitter_ratio=0.15, min_packets=5)

    def test_regular_beacon_pattern(self) -> None:
        flow = make_dummy_flow()
        # Jitter ratio 0.05 is extremely periodic (low variance)
        features = make_dummy_features(jitter=0.05, total_packets=10)
        context = {"repetition_count": 8, "interval_sec": 60.0}
        signal = self.detector.detect(flow, features, context=context)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.C2_BEACONING)
        self.assertGreaterEqual(signal.confidence, 0.85)

    def test_irregular_normal_traffic(self) -> None:
        flow = make_dummy_flow()
        # High jitter (0.75) represents normal variable user traffic
        features = make_dummy_features(jitter=0.75, total_packets=10)
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_insufficient_timing_information(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features(total_packets=2)
        features.timing.jitter_ratio = None
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)


class TestDNSDetectors(unittest.TestCase):
    """Test DNS DGA and Tunneling rule detectors."""

    def setUp(self) -> None:
        self.dga_detector = DNSDGARuleDetector(min_entropy=3.8, min_query_length=15)
        self.tunnel_detector = DNSTunnelingRuleDetector(min_query_length=65, min_subdomain_depth=4)

    def test_dga_high_entropy(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP, dst_port=53)
        features = make_dummy_features(dns=True, query="a89fdk23jklmz09x8q.biz", entropy=4.2)
        features.dns.is_nxdomain = True
        signal = self.dga_detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.DNS_DGA)

    def test_dga_normal_domain(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP, dst_port=53)
        features = make_dummy_features(dns=True, query="google.com", entropy=2.4)
        signal = self.dga_detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_dns_tunneling(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP, dst_port=53)
        tunnel_query = "c2hhMjU2ZXhhbXBsZWRhdGFleGZpbHRyYXRpb25wYXlsb2FkMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY.data.tunnel.example.com"
        features = make_dummy_features(dns=True, query=tunnel_query, entropy=4.1)
        features.dns.query_length = len(tunnel_query)
        features.dns.subdomain_depth = 5
        features.dns.unique_char_ratio = 0.65
        signal = self.tunnel_detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.DNS_TUNNELING)

    def test_missing_dns_metadata(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.UDP, dst_port=53)
        features = make_dummy_features(dns=False)
        self.assertIsNone(self.dga_detector.detect(flow, features))
        self.assertIsNone(self.tunnel_detector.detect(flow, features))


class TestSuspiciousTLSDetector(unittest.TestCase):
    """Test passive TLS metadata rule detector."""

    def setUp(self) -> None:
        self.detector = SuspiciousTLSRuleDetector(
            flag_deprecated_versions=True,
            flag_missing_sni_on_443=True,
            min_cipher_suites=2,
            suspicious_ja3_hashes={"bad_ja3_hash_123"},
        )

    def test_suspicious_tls_deprecated_version(self) -> None:
        flow = make_dummy_flow(dst_port=443)
        features = make_dummy_features(tls=True, tls_version="TLS 1.0", sni=True, cipher_count=10)
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.SUSPICIOUS_TLS)
        self.assertTrue(any(ev.feature_name == "tls_version" for ev in signal.evidence))

    def test_suspicious_tls_missing_sni_on_443(self) -> None:
        flow = make_dummy_flow(dst_port=443)
        features = make_dummy_features(tls=True, tls_version="TLS 1.3", sni=False, cipher_count=15)
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.SUSPICIOUS_TLS)
        self.assertTrue(any(ev.feature_name == "sni_present" for ev in signal.evidence))

    def test_suspicious_ja3_blacklist_match(self) -> None:
        flow = make_dummy_flow(dst_port=443)
        features = make_dummy_features(tls=True, tls_version="TLS 1.3", sni=True, cipher_count=15)
        features.tls.ja3_hash = "bad_ja3_hash_123"
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.severity, DetectionSeverity.HIGH)

    def test_normal_tls(self) -> None:
        flow = make_dummy_flow(dst_port=443)
        features = make_dummy_features(tls=True, tls_version="TLS 1.3", sni=True, cipher_count=16)
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_missing_tls_metadata(self) -> None:
        flow = make_dummy_flow(dst_port=80)
        features = make_dummy_features(tls=False)
        self.assertIsNone(self.detector.detect(flow, features))


class TestDataExfiltrationDetector(unittest.TestCase):
    """Test Data exfiltration rule detector."""

    def setUp(self) -> None:
        self.detector = DataExfiltrationRuleDetector(
            min_outbound_bytes=10_000_000,
            min_byte_asymmetry_ratio=0.85,
            min_bps=100_000.0,
        )

    def test_extreme_outbound_ratio(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features(
            outbound_bytes=50_000_000,
            inbound_bytes=100_000,
            bps=500_000.0,
            duration=100.0,
        )
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.DATA_EXFILTRATION)
        self.assertEqual(signal.severity, DetectionSeverity.HIGH)

    def test_normal_asymmetric_download(self) -> None:
        flow = make_dummy_flow()
        # Normal client download: high inbound, low outbound
        features = make_dummy_features(
            outbound_bytes=50_000,
            inbound_bytes=50_000_000,
            bps=500_000.0,
            duration=100.0,
        )
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_insufficient_evidence(self) -> None:
        flow = make_dummy_flow()
        # High ratio but total bytes is tiny (e.g. 1000 bytes)
        features = make_dummy_features(
            outbound_bytes=1000,
            inbound_bytes=10,
            bps=1000.0,
            duration=1.0,
        )
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)


class TestStatisticalAnomalyDetector(unittest.TestCase):
    """Test Statistical baseline and Z-score anomaly detector."""

    def setUp(self) -> None:
        self.detector = StatisticalAnomalyDetector(z_threshold=3.5)

    def test_obvious_anomaly(self) -> None:
        flow = make_dummy_flow()
        # Default baseline pps is mean=10, std=25. Set pps=200 -> z > 7.0!
        features = make_dummy_features(pps=200.0, total_packets=500)
        signal = self.detector.detect(flow, features)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.threat_type, ThreatType.BEHAVIORAL_ANOMALY)
        self.assertEqual(signal.detector_type, DetectorType.STATISTICAL)
        self.assertTrue(len(signal.evidence) >= 1)

    def test_normal_baseline(self) -> None:
        flow = make_dummy_flow()
        # Rates within 1 std dev of baseline
        features = make_dummy_features(pps=12.0, bps=1800.0, duration=5.0, outbound_bytes=5500)
        signal = self.detector.detect(flow, features)
        self.assertIsNone(signal)

    def test_baseline_update(self) -> None:
        # Fit new baseline on normal samples
        samples = [make_dummy_features(pps=100.0 + i) for i in range(10)]
        self.detector.update_baseline(samples)
        # Now pps=105 should not be an anomaly
        flow = make_dummy_flow()
        normal_feat = make_dummy_features(pps=105.0)
        self.assertIsNone(self.detector.detect(flow, normal_feat))


class TestRandomForestMLDetector(unittest.TestCase):
    """Test Supervised Random Forest ML inference detector."""

    def setUp(self) -> None:
        self.detector = RandomForestMLDetector(min_confidence=0.50)

    def test_model_loading_and_metadata(self) -> None:
        self.assertIsNotNone(self.detector.model)
        self.assertEqual(self.detector.metadata.algorithm, "RandomForestClassifier")
        self.assertIn("SYN_FLOOD", self.detector.metadata.target_classes)
        self.assertIn("PORT_SCAN", self.detector.metadata.target_classes)
        self.assertEqual(self.detector.detector_type, DetectorType.ML)

    def test_deterministic_prediction(self) -> None:
        flow = make_dummy_flow()
        # Provide SYN flood profile features
        features = make_dummy_features(pps=150.0, total_packets=100, outbound_packets=100, inbound_packets=0)
        signal = self.detector.detect(flow, features)
        # Should detect a threat and provide machine-readable evidence
        if signal is not None:
            self.assertEqual(signal.detector_type, DetectorType.ML)
            self.assertGreaterEqual(signal.confidence, 0.50)
            self.assertTrue(len(signal.evidence) > 0)
            self.assertIn("class_probabilities", signal.metadata)

    def test_missing_feature_handling(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        # Clear timing features to test imputation
        features.timing.jitter_ratio = None
        features.timing.inter_arrival_std_sec = None
        signal = self.detector.detect(flow, features)
        # Should not throw exception; handles missing features safely

    def test_invalid_model_path_handling(self) -> None:
        with self.assertRaises(FileNotFoundError):
            RandomForestMLDetector(model_path="non_existent_model.joblib", metadata_path="non_existent_meta.json")

    def test_artifact_save_and_reload(self) -> None:
        clf, meta = create_deterministic_baseline_model()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model_file = save_model_artifacts(clf, meta, tmp_path)
            meta_file = tmp_path / f"{meta.model_name}.json"
            self.assertTrue(model_file.exists())
            self.assertTrue(meta_file.exists())

            reloaded_detector = RandomForestMLDetector(model_path=model_file, metadata_path=meta_file)
            self.assertEqual(reloaded_detector.metadata.model_name, meta.model_name)


class TestEnsembleCorrelation(unittest.TestCase):
    """Test Ensemble correlation and combination engine."""

    def setUp(self) -> None:
        self.ensemble = EnsembleCorrelationEngine(agreement_bonus=0.10, min_consensus_confidence=0.50)

    def test_no_detection_benign(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        result = self.ensemble.correlate(flow, features, signals=[])
        self.assertFalse(result.is_threat)
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.severity, DetectionSeverity.INFO)
        self.assertEqual(result.confidence, 0.0)

    def test_single_detector_pass_through(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        sig = DetectionSignal(
            signal_id="sig_1",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.RULE,
            detector_name="syn_flood_rule",
            confidence=0.88,
            severity=DetectionSeverity.HIGH,
            evidence=[DetectionEvidence(feature_name="syn_count", observed_value=50, description="SYN burst")],
            description="SYN Flood",
        )
        result = self.ensemble.correlate(flow, features, signals=[sig])
        self.assertTrue(result.is_threat)
        self.assertEqual(result.threat_type, ThreatType.SYN_FLOOD)
        self.assertEqual(result.confidence, 0.88)
        self.assertEqual(result.severity, DetectionSeverity.HIGH)
        self.assertEqual(len(result.signals), 1)

    def test_multiple_agreeing_detectors_bonus(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        sig_rule = DetectionSignal(
            signal_id="sig_rule",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.RULE,
            detector_name="syn_flood_rule",
            confidence=0.85,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="Rule SYN",
        )
        sig_ml = DetectionSignal(
            signal_id="sig_ml",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.ML,
            detector_name="ml_rf",
            confidence=0.80,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="ML SYN",
        )
        result = self.ensemble.correlate(flow, features, signals=[sig_rule, sig_ml])
        self.assertTrue(result.is_threat)
        self.assertEqual(result.threat_type, ThreatType.SYN_FLOOD)
        self.assertEqual(result.detector_type, DetectorType.ENSEMBLE)
        # With agreement bonus (+0.10), combined confidence should exceed base weighted average
        self.assertGreater(result.confidence, 0.85)
        self.assertEqual(len(result.signals), 2)

    def test_conflicting_detectors(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        sig1 = DetectionSignal(
            signal_id="sig_1",
            threat_type=ThreatType.UDP_FLOOD,
            detector_type=DetectorType.RULE,
            detector_name="udp_flood_rule",
            confidence=0.92,
            severity=DetectionSeverity.HIGH,
            evidence=[],
            description="Rule UDP",
        )
        sig2 = DetectionSignal(
            signal_id="sig_2",
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            detector_type=DetectorType.STATISTICAL,
            detector_name="stat_anomaly",
            confidence=0.70,
            severity=DetectionSeverity.MEDIUM,
            evidence=[],
            description="Stat Anomaly",
        )
        result = self.ensemble.correlate(flow, features, signals=[sig1, sig2])
        self.assertTrue(result.is_threat)
        # Winning threat should be UDP_FLOOD due to higher confidence
        self.assertEqual(result.threat_type, ThreatType.UDP_FLOOD)
        # But both contributing signals must be retained!
        self.assertEqual(len(result.signals), 2)


class TestDetectionPipelineIntegration(unittest.TestCase):
    """End-to-end integration tests for the full hybrid DetectionPipeline."""

    def setUp(self) -> None:
        self.pipeline = create_default_detection_pipeline()

    def test_pipeline_registration_and_disable(self) -> None:
        self.assertGreaterEqual(len(self.pipeline.registered_detectors), 10)
        self.assertTrue(self.pipeline.disable_detector("syn_flood_rule"))
        self.assertFalse(self.pipeline.get_detector("syn_flood_rule").enabled)
        self.assertTrue(self.pipeline.enable_detector("syn_flood_rule"))
        self.assertTrue(self.pipeline.get_detector("syn_flood_rule").enabled)

    def test_pipeline_normal_traffic_end_to_end(self) -> None:
        flow = make_dummy_flow()
        features = make_dummy_features()
        result = self.pipeline.analyze(flow, features)
        self.assertFalse(result.is_threat)
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.severity, DetectionSeverity.INFO)

    def test_pipeline_syn_flood_end_to_end(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        features = make_dummy_features(syn_count=120, ack_count=2, pps=60.0, total_packets=122)
        result = self.pipeline.analyze(flow, features)
        self.assertTrue(result.is_threat)
        self.assertEqual(result.threat_type, ThreatType.SYN_FLOOD)
        self.assertIn(result.severity, (DetectionSeverity.HIGH, DetectionSeverity.CRITICAL))
        # Ensure evidence is machine-readable and traceable
        self.assertTrue(len(result.evidence) > 0)
        self.assertEqual(result.evidence[0].feature_name, "tcp_syn_count")
        self.assertEqual(result.evidence[0].observed_value, 120)

    def test_evidence_deterministic_serialization(self) -> None:
        flow = make_dummy_flow(protocol=ProtocolType.TCP)
        features = make_dummy_features(syn_count=120, ack_count=2, pps=60.0, total_packets=122)
        result = self.pipeline.analyze(flow, features)
        json_output = result.to_json()
        parsed = json.loads(json_output)
        self.assertEqual(parsed["flow_id"], flow.flow_id)
        self.assertEqual(parsed["threat_type"], "SYN_FLOOD")
        self.assertIn("evidence", parsed)
        self.assertTrue(isinstance(parsed["evidence"], list))


class TestSeverityPolicy(unittest.TestCase):
    """Test confidence vs severity separation policy."""

    def test_confidence_does_not_dictate_severity(self) -> None:
        # High confidence (0.99) in a low-impact threat should NOT become CRITICAL
        sev = evaluate_severity(
            threat_type=ThreatType.PORT_SCAN,
            confidence=0.99,
            context={"scanned_ports_count": 5},
        )
        self.assertNotEqual(sev, DetectionSeverity.CRITICAL)
        self.assertEqual(sev, DetectionSeverity.LOW)

    def test_volumetric_escalation(self) -> None:
        evidence = [
            DetectionEvidence(feature_name="tcp_syn_count", observed_value=1000, description="Massive SYN")
        ]
        sev = evaluate_severity(
            threat_type=ThreatType.SYN_FLOOD,
            confidence=0.85,
            evidence=evidence,
        )
        self.assertEqual(sev, DetectionSeverity.CRITICAL)


if __name__ == "__main__":
    unittest.main()

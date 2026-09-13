import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from datetime import datetime, timezone
import threading
import unittest

from sentinel_detection.rules.stateful_c2 import StatefulC2BeaconingDetector
from sentinel_models.detection import DetectionSeverity, DetectorType, ThreatType
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import (
    FeatureVector,
    NetworkFeatures,
    TimingFeatures,
)


def make_test_flow(
    src_ip: str = "192.168.10.15",
    dst_ip: str = "205.174.165.73",
    src_port: int = 49152,
    dst_port: int = 8080,
    protocol: ProtocolType = ProtocolType.TCP,
    duration_sec: float = 1.0,
    total_packets: int = 6,
    total_bytes: int = 18,
    timestamp: float = 1000.0,
) -> FlowRecord:
    """Helper creating a test FlowRecord."""
    dt = datetime.fromtimestamp(timestamp, timezone.utc)
    return FlowRecord(
        flow_id=f"flow_{src_ip}_{dst_ip}_{dst_port}_{timestamp}",
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        start_time=dt,
        last_seen_time=dt,
        duration_sec=duration_sec,
        total_packets=total_packets,
        total_bytes=total_bytes,
        forward_packets=total_packets // 2,
        backward_packets=total_packets - (total_packets // 2),
        forward_bytes=0,
        backward_bytes=total_bytes,
    )


def make_test_features(
    duration_sec: float = 1.0,
    total_packets: int = 6,
    total_bytes: int = 18,
    mean_iat: float = 0.20,
    jitter_ratio: float = 1.36,
) -> FeatureVector:
    """Helper creating a matching FeatureVector."""
    net = NetworkFeatures(
        duration_sec=duration_sec,
        total_packets=total_packets,
        total_bytes=total_bytes,
        forward_packets=total_packets // 2,
        backward_packets=total_packets - (total_packets // 2),
        forward_bytes=0,
        backward_bytes=total_bytes,
        packets_per_second=total_packets / max(0.001, duration_sec),
        bytes_per_second=total_bytes / max(0.001, duration_sec),
        forward_packets_per_second=(total_packets // 2) / max(0.001, duration_sec),
        backward_packets_per_second=(total_packets - (total_packets // 2)) / max(0.001, duration_sec),
        forward_backward_packet_ratio=1.0,
        forward_backward_byte_ratio=0.0,
        byte_asymmetry_ratio=0.0,
        mean_packet_size=total_bytes / max(1, total_packets),
        min_packet_size=0,
        max_packet_size=total_bytes,
        packet_size_std=3.2,
    )
    timing = TimingFeatures(
        mean_inter_arrival_sec=mean_iat,
        jitter_ratio=jitter_ratio,
    )
    return FeatureVector(
        flow_id="test_vec",
        network=net,
        timing=timing,
    )


class TestStatefulC2BeaconingDetector(unittest.TestCase):
    """Unit test suite for StatefulC2BeaconingDetector."""

    def setUp(self) -> None:
        self.detector = StatefulC2BeaconingDetector(
            min_observations=4,
            max_jitter_ratio=0.25,
            min_interval_sec=1.0,
            max_interval_sec=3600.0,
            ttl_sec=3600.0,
        )

    def tearDown(self) -> None:
        self.detector.reset()

    def test_periodic_beacon_sequence(self) -> None:
        """Verify repeated periodic connections to the same endpoint trigger high-confidence C2 alert."""
        base_time = 1700000000.0
        interval = 10.0  # Exactly 10.0s apart

        # Send first 3 flows (k < 4, should NOT alert yet)
        for i in range(3):
            t = base_time + i * interval
            flow = make_test_flow(timestamp=t)
            feats = make_test_features()
            signal = self.detector.detect(flow, feats, context={"timestamp": t})
            self.assertIsNone(signal, f"Flow {i+1} should not trigger before min_observations")

        # 4th flow (k = 4, exactly 10s intervals -> CV = 0.0 -> should alert)
        t4 = base_time + 3 * interval
        flow4 = make_test_flow(timestamp=t4)
        feats4 = make_test_features()
        signal4 = self.detector.detect(flow4, feats4, context={"timestamp": t4})

        self.assertIsNotNone(signal4)
        self.assertEqual(signal4.threat_type, ThreatType.C2_BEACONING)
        self.assertEqual(signal4.detector_type, DetectorType.RULE)
        self.assertEqual(signal4.detector_name, "stateful_c2_beaconing_rule")
        self.assertEqual(signal4.severity, DetectionSeverity.HIGH)
        self.assertGreaterEqual(signal4.confidence, 0.78)
        self.assertAlmostEqual(signal4.metadata["period_sec"], 10.0, places=2)
        self.assertAlmostEqual(signal4.metadata["jitter_ratio"], 0.0, places=3)
        self.assertEqual(signal4.metadata["flow_count"], 4)

        # 5th flow (k = 5, continues to alert with observation count bonus)
        t5 = base_time + 4 * interval
        flow5 = make_test_flow(timestamp=t5)
        feats5 = make_test_features()
        signal5 = self.detector.detect(flow5, feats5, context={"timestamp": t5})
        self.assertIsNotNone(signal5)
        self.assertEqual(signal5.metadata["flow_count"], 5)
        self.assertGreater(signal5.confidence, signal4.confidence)

    def test_irregular_benign_traffic(self) -> None:
        """Verify irregular, variable inter-arrival traffic does not trigger false alerts."""
        base_time = 1700000000.0
        # Highly irregular timing: 1s, 45s, 3s, 120s, 5s (CV > 0.50)
        offsets = [0.0, 1.0, 46.0, 49.0, 169.0, 174.0]

        for off in offsets:
            t = base_time + off
            flow = make_test_flow(dst_port=443, total_bytes=1500, timestamp=t)
            feats = make_test_features(total_bytes=1500)
            signal = self.detector.detect(flow, feats, context={"timestamp": t})
            self.assertIsNone(signal, "Irregular benign traffic should not trigger C2 detection")

    def test_repeated_destination_requirement(self) -> None:
        """Verify flows to scattered different destinations do not trigger detection."""
        base_time = 1700000000.0
        # 5 flows, but each goes to a different destination IP
        for i in range(5):
            t = base_time + i * 10.0
            flow = make_test_flow(dst_ip=f"10.0.0.{i+1}", timestamp=t)
            feats = make_test_features()
            signal = self.detector.detect(flow, feats, context={"timestamp": t})
            self.assertIsNone(signal, "Scattered destination flows should not accumulate history")

    def test_insufficient_observations(self) -> None:
        """Verify no signal is emitted before reaching min_observations threshold."""
        flow = make_test_flow(timestamp=100.0)
        feats = make_test_features()
        self.assertIsNone(self.detector.detect(flow, feats, context={"timestamp": 100.0}))
        self.assertIsNone(self.detector.detect(flow, feats, context={"timestamp": 110.0}))
        self.assertEqual(self.detector.active_endpoint_count, 1)

    def test_state_expiration_ttl(self) -> None:
        """Verify state older than ttl_sec is pruned and does not false alert."""
        det = StatefulC2BeaconingDetector(min_observations=4, ttl_sec=60.0)

        # Send 3 flows at t=0, 10, 20
        for i in range(3):
            t = float(i * 10)
            flow = make_test_flow(timestamp=t)
            feats = make_test_features()
            det.detect(flow, feats, context={"timestamp": t})

        # Send 4th flow after TTL expired (>60s gap: t=120)
        t_late = 120.0
        flow_late = make_test_flow(timestamp=t_late)
        feats_late = make_test_features()
        sig = det.detect(flow_late, feats_late, context={"timestamp": t_late})
        self.assertIsNone(sig, "Flow arriving after TTL should reset observation history")

    def test_bounded_state_capacity(self) -> None:
        """Verify max_tracked_endpoints bounds memory and evicts via LRU."""
        det = StatefulC2BeaconingDetector(max_tracked_endpoints=10, min_observations=4)

        # Register 25 distinct endpoints
        for i in range(25):
            flow = make_test_flow(dst_ip=f"198.51.100.{i}", timestamp=1000.0 + i)
            feats = make_test_features()
            det.detect(flow, feats)

        self.assertEqual(det.active_endpoint_count, 10, "Capacity must be bounded strictly to max_tracked_endpoints")

    def test_multiple_hosts_isolation(self) -> None:
        """Verify distinct host sessions are tracked independently without cross-talk."""
        base_time = 1700000000.0
        interval = 15.0

        # Host A (Bot) sends 4 periodic flows
        sig_a = None
        for i in range(4):
            t = base_time + i * interval
            flow_a = make_test_flow(src_ip="192.168.1.50", dst_ip="203.0.113.1", timestamp=t)
            feats_a = make_test_features()
            sig_a = self.detector.detect(flow_a, feats_a, context={"timestamp": t})

        # Host B (Benign) sends 4 irregular flows
        sig_b = None
        irregular_offsets = [0.0, 2.0, 85.0, 190.0]
        for off in irregular_offsets:
            t = base_time + off
            flow_b = make_test_flow(src_ip="192.168.1.99", dst_ip="203.0.113.2", dst_port=443, timestamp=t)
            feats_b = make_test_features()
            sig_b = self.detector.detect(flow_b, feats_b, context={"timestamp": t})

        self.assertIsNotNone(sig_a, "Host A (periodic beacon) must be detected")
        self.assertEqual(sig_a.threat_type, ThreatType.C2_BEACONING)
        self.assertIsNone(sig_b, "Host B (irregular) must NOT be detected")

    def test_ntp_exclusion(self) -> None:
        """Verify legitimate periodic NTP traffic (port 123) is explicitly excluded."""
        for i in range(5):
            t = 1000.0 + i * 10.0
            flow = make_test_flow(dst_port=123, timestamp=t)
            feats = make_test_features()
            sig = self.detector.detect(flow, feats, context={"timestamp": t})
            self.assertIsNone(sig, "NTP traffic on port 123 must be excluded")

    def test_thread_safety_concurrency(self) -> None:
        """Verify concurrent updates across multiple threads execute without race conditions."""
        det = StatefulC2BeaconingDetector(max_tracked_endpoints=500, min_observations=4)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(20):
                    t = 1000.0 + i * 5.0
                    flow = make_test_flow(
                        src_ip=f"192.168.{worker_id}.1",
                        dst_ip=f"10.0.{worker_id}.2",
                        timestamp=t,
                    )
                    feats = make_test_features()
                    det.detect(flow, feats, context={"timestamp": t})
            except Exception as ex:
                errors.append(ex)

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(len(errors), 0, f"Concurrent execution produced errors: {errors}")
        self.assertLessEqual(det.active_endpoint_count, 500)

    def test_deterministic_behavior_and_reset(self) -> None:
        """Verify reset clears state and deterministic replay yields identical results."""
        seq_times = [1000.0, 1010.0, 1020.0, 1030.0]

        # Run 1
        signals_run1 = []
        for t in seq_times:
            flow = make_test_flow(timestamp=t)
            feats = make_test_features()
            sig = self.detector.detect(flow, feats, context={"timestamp": t})
            signals_run1.append(sig)

        self.assertEqual(self.detector.active_endpoint_count, 1)
        self.detector.reset()
        self.assertEqual(self.detector.active_endpoint_count, 0)

        # Run 2
        signals_run2 = []
        for t in seq_times:
            flow = make_test_flow(timestamp=t)
            feats = make_test_features()
            sig = self.detector.detect(flow, feats, context={"timestamp": t})
            signals_run2.append(sig)

        self.assertEqual(len(signals_run1), len(signals_run2))
        self.assertIsNone(signals_run1[0])
        self.assertIsNone(signals_run2[0])
        self.assertIsNotNone(signals_run1[3])
        self.assertIsNotNone(signals_run2[3])
        self.assertEqual(signals_run1[3].confidence, signals_run2[3].confidence)

    def test_cic_ids_bot_replay(self) -> None:
        """Deterministic synthetic sequence modeling the CIC-IDS2017 Ares Botnet pattern."""
        # Ares botnet: periodic keep-alives to port 8080, small 6-packet flows, 18 bytes
        det = StatefulC2BeaconingDetector(
            min_observations=4,
            max_jitter_ratio=0.25,
            min_interval_sec=0.5,
            max_interval_sec=3600.0,
        )

        bot_ip = "192.168.10.15"
        c2_ip = "205.174.165.73"
        c2_port = 8080
        base_time = 1499425200.0  # Friday July 7, 2017 approx epoch
        interval = 60.0  # 60s periodic polling

        signals = []
        for k in range(6):
            t = base_time + k * interval
            flow = make_test_flow(
                src_ip=bot_ip,
                dst_ip=c2_ip,
                dst_port=c2_port,
                duration_sec=1.01,
                total_packets=6,
                total_bytes=18,
                timestamp=t,
            )
            feats = make_test_features(
                duration_sec=1.01,
                total_packets=6,
                total_bytes=18,
                mean_iat=0.20,
                jitter_ratio=1.36,  # Single-flow intra-flow jitter is high
            )
            sig = det.detect(flow, feats, context={"timestamp": t})
            signals.append(sig)

        # Flows 0..2 should be None (k < 4)
        self.assertIsNone(signals[0])
        self.assertIsNone(signals[1])
        self.assertIsNone(signals[2])

        # Flow 3 (4th flow): multi-flow periodicity detected
        self.assertIsNotNone(signals[3])
        self.assertEqual(signals[3].threat_type, ThreatType.C2_BEACONING)
        self.assertEqual(signals[3].detector_type, DetectorType.RULE)
        self.assertGreaterEqual(signals[3].confidence, 0.78)

        # Flows 4 and 5 also alert with high confidence
        self.assertIsNotNone(signals[4])
        self.assertIsNotNone(signals[5])
        self.assertGreaterEqual(signals[5].confidence, 0.82)


if __name__ == "__main__":
    unittest.main()

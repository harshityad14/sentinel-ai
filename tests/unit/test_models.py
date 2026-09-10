"""Unit tests for SentinelAI core domain models."""

import unittest
from datetime import datetime, timezone
from sentinel_models import (
    Alert,
    AlertEvidence,
    AlertSeverity,
    MitreAttackRef,
    PacketMetadata,
    FlowRecord,
    ProtocolType,
    TCPFlags,
    ThreatCategory,
    TelemetrySnapshot,
    IngestionMetrics,
    FlowMetrics,
    DetectionLatencyMetrics,
)


class TestSentinelModels(unittest.TestCase):
    def test_packet_metadata_creation(self):
        pkt = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=80,
            protocol=ProtocolType.TCP,
            packet_length=1500,
            payload_length=1460,
            tcp_flags=TCPFlags(syn=True, ack=False),
        )
        self.assertEqual(pkt.source_ip, "192.168.1.50")
        self.assertEqual(pkt.destination_port, 80)
        self.assertTrue(pkt.tcp_flags.syn)
        self.assertFalse(pkt.tcp_flags.ack)

    def test_flow_record_creation(self):
        now = datetime.now(timezone.utc)
        flow = FlowRecord(
            flow_id="flow_192.168.1.50_80_10.0.0.1_54321_TCP",
            start_time=now,
            last_seen_time=now,
            duration_sec=12.5,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=80,
            protocol=ProtocolType.TCP,
            forward_packets=10,
            backward_packets=8,
            forward_bytes=5200,
            backward_bytes=3100,
        )
        self.assertEqual(flow.forward_packets, 10)
        self.assertEqual(flow.backward_packets, 8)
        self.assertTrue(flow.is_active)

    def test_alert_creation_with_mitre_and_evidence(self):
        now = datetime.now(timezone.utc)
        mitre = MitreAttackRef(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Application Layer Protocol",
            technique_id="T1071",
            subtechnique_id="T1071.001",
        )
        evidence = AlertEvidence(
            detector_name="beaconing_detector",
            detection_type="statistical",
            triggered_features={"interval_jitter_pct": 2.1, "periodicity_score": 0.98},
            raw_indicators={"total_observations": 120},
        )
        alert = Alert(
            alert_id="alt_test_001",
            timestamp=now,
            category=ThreatCategory.C2_BEACONING,
            severity=AlertSeverity.HIGH,
            confidence=0.95,
            risk_score=85,
            source_ip="192.168.1.100",
            destination_ip="198.51.100.20",
            destination_port=443,
            protocol="TCP",
            mitre_attack=mitre,
            evidence=[evidence],
            explanation="Periodic C2 beaconing pattern detected with 2.1% timing jitter.",
        )
        self.assertEqual(alert.category, ThreatCategory.C2_BEACONING)
        self.assertEqual(alert.risk_score, 85)
        self.assertEqual(len(alert.evidence), 1)
        self.assertEqual(alert.mitre_attack.technique_id, "T1071")

    def test_telemetry_snapshot_metrics(self):
        now = datetime.now(timezone.utc)
        snapshot = TelemetrySnapshot(
            timestamp=now,
            ingestion=IngestionMetrics(
                packets_ingested_total=50000,
                bytes_ingested_total=35000000,
                ingestion_throughput_pps=12500.0,
            ),
            flows=FlowMetrics(
                flows_active_count=320,
                flows_completed_total=4500,
                flow_throughput_fps=1200.0,
            ),
            detection_latency=DetectionLatencyMetrics(
                avg_latency_ms=18.4,
                p95_latency_ms=35.0,
                p99_latency_ms=62.1,
                max_latency_ms=95.0,
            ),
        )
        self.assertEqual(snapshot.ingestion.ingestion_throughput_pps, 12500.0)
        self.assertEqual(snapshot.flows.flow_throughput_fps, 1200.0)
        self.assertEqual(snapshot.detection_latency.avg_latency_ms, 18.4)


if __name__ == "__main__":
    unittest.main()

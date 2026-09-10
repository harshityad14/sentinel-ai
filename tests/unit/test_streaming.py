"""Unit test suite for SentinelAI Phase 6 real-time streaming pipeline."""

from datetime import datetime, timezone
import json
import unittest

from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    RiskScore,
    SecurityAlert,
)
from sentinel_models.detection import DetectionEvidence, DetectionResult, DetectionSeverity, DetectorType, ThreatType
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector
from sentinel_streaming.bus import MemoryStreamingBus, StreamMessage
from sentinel_streaming.config import StreamingConfig
from sentinel_streaming.reliability.dead_letter import build_dlq_envelope
from sentinel_streaming.reliability.deduplicator import (
    IdempotencyDeduplicator,
    generate_deterministic_event_id,
)
from sentinel_streaming.reliability.retry_handler import RetryHandler, is_retryable_exception
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import (
    SENTINEL_TOPICS,
    TOPIC_ALERTS_CORRELATED,
    TOPIC_DETECTIONS_RAW,
    TOPIC_FLOWS_FEATURES,
    TOPIC_FLOWS_RAW,
    TOPIC_PIPELINE_DLQ,
    get_alert_partition_key,
    get_detection_partition_key,
    get_flow_feature_partition_key,
    get_flow_raw_partition_key,
)
from sentinel_streaming.workers.alert_persistence_worker import AlertPersistenceWorker
from sentinel_streaming.workers.detection_correlation_worker import DetectionCorrelationWorker
from sentinel_streaming.workers.feature_detection_worker import FeatureDetectionWorker
from sentinel_streaming.workers.flow_feature_worker import FlowFeatureWorker


def make_sample_flow() -> FlowRecord:
    """Helper creating a realistic FlowRecord for streaming tests."""
    now = datetime.now(timezone.utc)
    return FlowRecord(
        flow_id="flow-stream-001",
        start_time=now,
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        source_port=49152,
        destination_port=445,
        protocol=ProtocolType.TCP,
        total_packets=150,
        total_bytes=12500,
        duration_sec=2.5,
        forward_packets=120,
        backward_packets=30,
        forward_bytes=10000,
        backward_bytes=2500,
        tcp_flags={"syn": 1, "ack": 145, "fin": 1, "rst": 0},
        termination_reason="NORMAL",
    )


def make_sample_alert() -> SecurityAlert:
    """Helper creating a valid Phase 4 SecurityAlert."""
    now = datetime.now(timezone.utc)
    return SecurityAlert(
        alert_id="alert-stream-001",
        correlation_group_id="group-stream-001",
        title="Streaming Test Alert: Port Scan Detected",
        threat_class=ThreatType.PORT_SCAN,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        confidence=0.92,
        risk_score=RiskScore(score=82, confidence_factor=0.92, severity_factor=0.85, breakdown={"base": 80.0, "confidence": 0.92}),
        first_seen=now,
        last_seen=now,
        flow_ids=["flow-stream-001"],
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        contributing_signals=[
            AlertSignal(
                signal_id="sig-stream-001",
                flow_id="flow-stream-001",
                detector_type="RULE",
                detector_name="RuleBasedDetector",
                threat_type="PORT_SCAN",
                severity="HIGH",
                confidence=0.95,
                timestamp=now,
            )
        ],
        evidence=[
            AlertEvidence(
                detector_name="RuleBasedDetector",
                description="High port scan fan-out rate",
                raw_indicators={"ports_contacted": 120},
                confidence_contribution=0.9,
            )
        ],
        timestamp=now,
        explanation="High confidence port scan detected",
    )


class TestStreamingPipeline(unittest.TestCase):
    """Test suite verifying Phase 6 real-time streaming components and guarantees."""

    def test_stream_envelope_serialization(self):
        """Test StreamEnvelope serialization, deserialization, and schema validation."""
        flow = make_sample_flow()
        envelope = StreamEnvelope(
            event_id="evt-001",
            trace_id="tr-001",
            schema_name="FlowRecord",
            schema_version="1.0",
            source_stage="ingestion",
            payload=flow,
        )

        data = envelope.to_bytes()
        self.assertIsInstance(data, bytes)

        deserialized = StreamEnvelope.from_bytes(data, payload_cls=FlowRecord)
        self.assertEqual(deserialized.event_id, "evt-001")
        self.assertEqual(deserialized.trace_id, "tr-001")
        self.assertEqual(deserialized.schema_name, "FlowRecord")
        self.assertEqual(deserialized.payload.flow_id, flow.flow_id)
        self.assertEqual(deserialized.payload.source_ip, flow.source_ip)

    def test_stream_envelope_version_compatibility(self):
        """Test schema version checks for backward compatibility."""
        flow = make_sample_flow()
        # Compatible minor version (1.1 should parse under 1.0 expectations)
        env_minor = StreamEnvelope(
            event_id="evt-002",
            trace_id="tr-002",
            schema_name="FlowRecord",
            schema_version="1.1",
            source_stage="ingestion",
            payload=flow,
        )
        raw = env_minor.to_bytes()
        parsed = StreamEnvelope.from_bytes(raw, payload_cls=FlowRecord, expected_major_version=1)
        self.assertEqual(parsed.event_id, "evt-002")

        # Incompatible major version (2.0 should be rejected if expected is 1)
        env_major = StreamEnvelope(
            event_id="evt-003",
            trace_id="tr-003",
            schema_name="FlowRecord",
            schema_version="2.0",
            source_stage="ingestion",
            payload=flow,
        )
        raw_major = env_major.to_bytes()
        with self.assertRaises(ValueError):
            StreamEnvelope.from_bytes(raw_major, payload_cls=FlowRecord, expected_major_version=1)

    def test_partition_key_determinism(self):
        """Test that bi-directional flows map to the identical partition key."""
        flow = make_sample_flow()
        reverse_flow = FlowRecord(
            flow_id="flow-stream-002",
            start_time=flow.start_time,
            source_ip=flow.destination_ip,
            destination_ip=flow.source_ip,
            source_port=flow.destination_port,
            destination_port=flow.source_port,
            protocol=flow.protocol,
            total_packets=50,
            total_bytes=5000,
            duration_sec=1.2,
        )

        key_fwd = get_flow_raw_partition_key(flow)
        key_rev = get_flow_raw_partition_key(reverse_flow)
        self.assertEqual(key_fwd, key_rev, "Bi-directional flow must map to the exact same partition key")

        # Feature partition key uses flow_id
        feat_key = get_flow_feature_partition_key(flow)
        self.assertEqual(feat_key, flow.flow_id)

        # Alert partition key uses correlation group or entity
        alert = make_sample_alert()
        alert_key = get_alert_partition_key(alert)
        self.assertEqual(alert_key, alert.correlation_group_id)

    def test_idempotency_deduplicator(self):
        """Test LRU deduplicator capacity and deterministic child ID generation."""
        dedup = IdempotencyDeduplicator(max_size=3)

        self.assertFalse(dedup.is_duplicate("evt-1"))
        dedup.record_processed("evt-1")
        self.assertTrue(dedup.is_duplicate("evt-1"))

        # Add more to trigger LRU eviction
        dedup.record_processed("evt-2")
        dedup.record_processed("evt-3")
        dedup.record_processed("evt-4")  # Evicts evt-1

        self.assertFalse(dedup.is_duplicate("evt-1"), "evt-1 should have been evicted by LRU capacity")
        self.assertTrue(dedup.is_duplicate("evt-4"))

        # Deterministic child ID derivation
        child_id_1 = generate_deterministic_event_id("evt-parent", "detection_stage")
        child_id_2 = generate_deterministic_event_id("evt-parent", "detection_stage")
        self.assertEqual(child_id_1, child_id_2, "Derived event IDs must be strictly deterministic")

    def test_retry_handler_transient_recovery(self):
        """Test exponential backoff recovery on retryable exceptions."""
        retry = RetryHandler(max_retries=3, initial_backoff_sec=0.01, backoff_multiplier=1.5)
        attempts = 0

        def flaky_operation():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionError("Temporary network reset")
            return "SUCCESS"

        result = retry.execute(flaky_operation)
        self.assertEqual(result, "SUCCESS")
        self.assertEqual(attempts, 3)

    def test_retry_handler_non_retryable(self):
        """Test that non-retryable exceptions fail immediately."""
        retry = RetryHandler(max_retries=3, initial_backoff_sec=0.01)
        attempts = 0

        def fatal_operation():
            nonlocal attempts
            attempts += 1
            raise ValueError("Non-retryable schema error")

        with self.assertRaises(ValueError):
            retry.execute(fatal_operation)

        self.assertEqual(attempts, 1, "Non-retryable exceptions must fail immediately without retry")

    def test_dead_letter_envelope(self):
        """Test dead-letter queue message envelope generation and serialization."""
        err = ValueError("Malformed JSON structure")
        dlq = build_dlq_envelope(
            raw_payload="INVALID-PAYLOAD-DATA",
            error_stage="FlowFeatureWorker",
            error=err,
            source_topic=TOPIC_FLOWS_RAW,
            source_partition=1,
            source_offset=42,
            trace_id="tr-dlq-001",
        )

        self.assertEqual(dlq.error_stage, "FlowFeatureWorker")
        self.assertEqual(dlq.source_topic, TOPIC_FLOWS_RAW)
        self.assertEqual(dlq.source_partition, 1)
        self.assertEqual(dlq.source_offset, 42)
        self.assertIn("Malformed JSON", dlq.error_message)
        self.assertEqual(dlq.raw_payload, "INVALID-PAYLOAD-DATA")

        raw_bytes = dlq.to_bytes()
        self.assertIsInstance(raw_bytes, bytes)

    def test_memory_streaming_bus(self):
        """Test MemoryStreamingBus topic isolation and pub/sub polling."""
        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("group-a")

        consumer.subscribe(["topic-1"])

        producer.produce("topic-1", b"msg-1", key="k1")
        producer.produce("topic-2", b"msg-2", key="k2")
        producer.flush()

        msg1 = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg1)
        self.assertEqual(msg1.value, b"msg-1")
        self.assertEqual(msg1.topic, "topic-1")

        # topic-2 should not be visible to this consumer
        msg2 = consumer.poll(timeout=0.05)
        self.assertIsNone(msg2)

        consumer.commit_sync()
        consumer.close()

    def test_flow_feature_worker(self):
        """Test FlowFeatureWorker consuming raw flows and emitting feature vectors."""
        flow = make_sample_flow()
        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("feature-workers")

        worker = FlowFeatureWorker(consumer=consumer, producer=producer)
        worker.start()

        # Produce input raw flow envelope
        in_env = StreamEnvelope(
            event_id="evt-f01",
            trace_id="tr-f01",
            schema_name="FlowRecord",
            schema_version="1.0",
            source_stage="ingest",
            payload=flow,
        )
        producer.produce(TOPIC_FLOWS_RAW, in_env.to_bytes(), key=flow.flow_id)
        producer.flush()

        msg = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg)
        processed = worker.process_message(msg)
        self.assertTrue(processed)
        self.assertEqual(worker.processed_count, 1)

        # Check output emitted to TOPIC_FLOWS_FEATURES
        feat_consumer = bus.get_consumer("test-feat-consumer")
        feat_consumer.subscribe([TOPIC_FLOWS_FEATURES])
        feat_msg = feat_consumer.poll(timeout=0.1)
        self.assertIsNotNone(feat_msg)

        feat_env = StreamEnvelope.from_bytes(feat_msg.value, payload_cls=FeatureVector)
        self.assertEqual(feat_env.payload.flow_id, flow.flow_id)
        self.assertEqual(feat_env.payload.network.total_packets, flow.total_packets)
        self.assertIn("flow_record", feat_env.payload.context)
        worker.stop()

    def test_feature_detection_worker(self):
        """Test FeatureDetectionWorker evaluating feature vectors with detection pipeline."""
        flow = make_sample_flow()
        extractor = UnifiedFeatureExtractor()
        features = extractor.extract(flow)
        features.context["flow_record"] = flow.model_dump(mode="json")

        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("det-workers")

        worker = FeatureDetectionWorker(consumer=consumer, producer=producer)
        worker.start()

        in_env = StreamEnvelope(
            event_id="evt-d01",
            trace_id="tr-d01",
            schema_name="FeatureVector",
            schema_version="1.0",
            source_stage="feature_extraction",
            payload=features,
        )
        producer.produce(TOPIC_FLOWS_FEATURES, in_env.to_bytes(), key=features.flow_id)
        producer.flush()

        msg = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg)
        processed = worker.process_message(msg)
        self.assertTrue(processed)
        worker.stop()

    def test_detection_correlation_worker(self):
        """Test DetectionCorrelationWorker consuming detection results and emitting alerts."""
        now = datetime.now(timezone.utc)
        detection = DetectionResult(
            detection_id="det-stream-001",
            flow_id="flow-stream-001",
            detector_type=DetectorType.ENSEMBLE,
            detection_timestamp=now,
            threat_type=ThreatType.PORT_SCAN,
            severity=DetectionSeverity.HIGH,
            confidence=0.91,
            signals=[],
            evidence=[],
            context={"source_ip": "192.168.1.100", "destination_ip": "10.0.0.5"},
        )

        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("corr-workers")

        worker = DetectionCorrelationWorker(consumer=consumer, producer=producer)
        worker.start()

        in_env = StreamEnvelope(
            event_id="evt-c01",
            trace_id="tr-c01",
            schema_name="DetectionResult",
            schema_version="1.0",
            source_stage="detection_engine",
            payload=detection,
        )
        producer.produce(TOPIC_DETECTIONS_RAW, in_env.to_bytes(), key=detection.detection_id)
        producer.flush()

        msg = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg)
        processed = worker.process_message(msg)
        self.assertTrue(processed)

        # Correlated alert emitted
        alert_consumer = bus.get_consumer("test-alert-check")
        alert_consumer.subscribe([TOPIC_ALERTS_CORRELATED])
        alert_msg = alert_consumer.poll(timeout=0.1)
        self.assertIsNotNone(alert_msg)

        alert_env = StreamEnvelope.from_bytes(alert_msg.value, payload_cls=SecurityAlert)
        self.assertEqual(alert_env.payload.threat_class, ThreatType.PORT_SCAN)
        worker.stop()

    def test_alert_persistence_worker_in_memory(self):
        """Test AlertPersistenceWorker in-memory persistence sink."""
        alert = make_sample_alert()
        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("persist-workers")

        worker = AlertPersistenceWorker(consumer=consumer, session_factory=None)
        worker.start()

        in_env = StreamEnvelope(
            event_id="evt-p01",
            trace_id="tr-p01",
            schema_name="SecurityAlert",
            schema_version="1.0",
            source_stage="correlation_engine",
            payload=alert,
        )
        producer.produce(TOPIC_ALERTS_CORRELATED, in_env.to_bytes(), key=alert.alert_id)
        producer.flush()

        msg = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg)
        processed = worker.process_message(msg)
        self.assertTrue(processed)
        self.assertEqual(worker.persisted_count, 1)
        worker.stop()

    def test_end_to_end_streaming_pipeline(self):
        """Verify that a raw flow flows through all 4 workers end-to-end to create a persisted alert."""
        flow = make_sample_flow()
        bus = MemoryStreamingBus()
        producer = bus.get_producer()

        # Create consumers
        cons_feat = bus.get_consumer("cg-feat")
        cons_det = bus.get_consumer("cg-det")
        cons_corr = bus.get_consumer("cg-corr")
        cons_sink = bus.get_consumer("cg-sink")

        # Instantiate the 4 workers
        w_feat = FlowFeatureWorker(consumer=cons_feat, producer=producer)
        w_det = FeatureDetectionWorker(consumer=cons_det, producer=producer)
        w_corr = DetectionCorrelationWorker(consumer=cons_corr, producer=producer)
        w_sink = AlertPersistenceWorker(consumer=cons_sink, session_factory=None)

        w_feat.start()
        w_det.start()
        w_corr.start()
        w_sink.start()

        # Ingest raw flow to TOPIC_FLOWS_RAW
        in_env = StreamEnvelope(
            event_id="evt-e2e-raw",
            trace_id="tr-e2e-001",
            schema_name="FlowRecord",
            schema_version="1.0",
            source_stage="packet_ingestion",
            payload=flow,
        )
        producer.produce(TOPIC_FLOWS_RAW, in_env.to_bytes(), key=flow.flow_id)
        producer.flush()

        # Stage 1: Raw -> Features
        msg1 = cons_feat.poll(timeout=0.1)
        self.assertIsNotNone(msg1)
        self.assertTrue(w_feat.process_message(msg1))
        self.assertEqual(w_feat.processed_count, 1)

        # Stage 2: Features -> Detections
        msg2 = cons_det.poll(timeout=0.1)
        self.assertIsNotNone(msg2)
        self.assertTrue(w_det.process_message(msg2))
        self.assertEqual(w_det.processed_count, 1)

        # Stage 3: Detections -> Alerts (if threat flagged)
        msg3 = cons_corr.poll(timeout=0.1)
        if msg3 is not None:
            self.assertTrue(w_corr.process_message(msg3))

            # Stage 4: Alerts -> Sink
            msg4 = cons_sink.poll(timeout=0.1)
            if msg4 is not None:
                self.assertTrue(w_sink.process_message(msg4))
                self.assertGreaterEqual(w_sink.persisted_count, 1)

        w_feat.stop()
        w_det.stop()
        w_corr.stop()
        w_sink.stop()

    def test_worker_dlq_on_corrupted_payload(self):
        """Test that malformed JSON payloads are cleanly diverted to Dead-Letter Queue."""
        bus = MemoryStreamingBus()
        producer = bus.get_producer()
        consumer = bus.get_consumer("cg-corrupted")

        worker = FlowFeatureWorker(consumer=consumer, producer=producer)
        worker.start()

        # Produce invalid JSON to raw topic
        producer.produce(TOPIC_FLOWS_RAW, b"NOT_VALID_JSON{:::}", key="bad-key")
        producer.flush()

        msg = consumer.poll(timeout=0.1)
        self.assertIsNotNone(msg)

        # Processing should catch error and route to DLQ
        success = worker.process_message(msg)
        self.assertFalse(success)
        self.assertEqual(worker.dlq_count, 1)

        # Verify message landed on DLQ topic
        dlq_consumer = bus.get_consumer("cg-dlq-inspector")
        dlq_consumer.subscribe([TOPIC_PIPELINE_DLQ])
        dlq_msg = dlq_consumer.poll(timeout=0.1)
        self.assertIsNotNone(dlq_msg)
        self.assertIn(b"FlowFeatureWorker", dlq_msg.value)
        worker.stop()


if __name__ == "__main__":
    unittest.main()

"""SentinelAI real-time streaming pipeline package."""

from sentinel_streaming.bus import (
    KafkaStreamConsumer,
    KafkaStreamProducer,
    MemoryStreamingBus,
    StreamConsumer,
    StreamMessage,
    StreamProducer,
)
from sentinel_streaming.config import StreamingConfig
from sentinel_streaming.reliability.dead_letter import DeadLetterEnvelope, build_dlq_envelope
from sentinel_streaming.reliability.deduplicator import IdempotencyDeduplicator, generate_deterministic_event_id
from sentinel_streaming.reliability.retry_handler import RetryHandler, is_retryable_exception
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import (
    SENTINEL_TOPICS,
    TOPIC_ALERTS_CORRELATED,
    TOPIC_DETECTIONS_RAW,
    TOPIC_FLOWS_FEATURES,
    TOPIC_FLOWS_RAW,
    TOPIC_PIPELINE_DLQ,
    TopicDefinition,
    get_alert_partition_key,
    get_detection_partition_key,
    get_flow_feature_partition_key,
    get_flow_raw_partition_key,
)
from sentinel_streaming.workers import (
    AlertPersistenceWorker,
    BaseStreamWorker,
    DetectionCorrelationWorker,
    FeatureDetectionWorker,
    FlowFeatureWorker,
)

__all__ = [
    "StreamingConfig",
    "StreamProducer",
    "StreamConsumer",
    "StreamMessage",
    "KafkaStreamProducer",
    "KafkaStreamConsumer",
    "MemoryStreamingBus",
    "StreamEnvelope",
    "TopicDefinition",
    "SENTINEL_TOPICS",
    "TOPIC_FLOWS_RAW",
    "TOPIC_FLOWS_FEATURES",
    "TOPIC_DETECTIONS_RAW",
    "TOPIC_ALERTS_CORRELATED",
    "TOPIC_PIPELINE_DLQ",
    "get_flow_raw_partition_key",
    "get_flow_feature_partition_key",
    "get_detection_partition_key",
    "get_alert_partition_key",
    "IdempotencyDeduplicator",
    "generate_deterministic_event_id",
    "RetryHandler",
    "is_retryable_exception",
    "DeadLetterEnvelope",
    "build_dlq_envelope",
    "BaseStreamWorker",
    "FlowFeatureWorker",
    "FeatureDetectionWorker",
    "DetectionCorrelationWorker",
    "AlertPersistenceWorker",
]

"""Kafka topic specifications, partition strategies, and metadata registry."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class TopicMetadata:
    """Metadata specification for Kafka topics."""
    name: str
    num_partitions: int
    replication_factor: int
    cleanup_policy: str
    retention_ms: int
    description: str


TOPIC_FLOWS_RAW = "sentinel.flows.raw"
TOPIC_FLOWS_FEATURES = "sentinel.flows.features"
TOPIC_DETECTIONS_RAW = "sentinel.detections.raw"
TOPIC_ALERTS_CORRELATED = "sentinel.alerts.correlated"
TOPIC_PIPELINE_DLQ = "sentinel.pipeline.dlq"

# Registry of standard pipeline topics for SentinelAI
TOPIC_REGISTRY: Dict[str, TopicMetadata] = {
    TOPIC_FLOWS_RAW: TopicMetadata(
        name=TOPIC_FLOWS_RAW,
        num_partitions=6,
        replication_factor=1,
        cleanup_policy="delete",
        retention_ms=86400000,  # 24 hours
        description="Ingested raw network flow sessions",
    ),
    TOPIC_FLOWS_FEATURES: TopicMetadata(
        name=TOPIC_FLOWS_FEATURES,
        num_partitions=6,
        replication_factor=1,
        cleanup_policy="delete",
        retention_ms=86400000,  # 24 hours
        description="Computed flow feature vectors",
    ),
    TOPIC_DETECTIONS_RAW: TopicMetadata(
        name=TOPIC_DETECTIONS_RAW,
        num_partitions=6,
        replication_factor=1,
        cleanup_policy="delete",
        retention_ms=172800000,  # 48 hours
        description="Raw threat detections emitted by detectors",
    ),
    TOPIC_ALERTS_CORRELATED: TopicMetadata(
        name=TOPIC_ALERTS_CORRELATED,
        num_partitions=3,
        replication_factor=1,
        cleanup_policy="compact,delete",
        retention_ms=604800000,  # 7 days
        description="Aggregated and risk-scored security alerts",
    ),
    TOPIC_PIPELINE_DLQ: TopicMetadata(
        name=TOPIC_PIPELINE_DLQ,
        num_partitions=2,
        replication_factor=1,
        cleanup_policy="delete",
        retention_ms=1209600000,  # 14 days
        description="Dead-letter queue for unprocessable or corrupt events",
    ),
}


def get_canonical_endpoint_key(source_ip: str, destination_ip: str) -> str:
    """Deterministic bidirectional endpoint key ensuring both directions route to same partition.
    
    Example:
        ("192.168.1.5", "10.0.0.1") -> "10.0.0.1:192.168.1.5"
        ("10.0.0.1", "192.168.1.5") -> "10.0.0.1:192.168.1.5"
    """
    first, second = sorted([source_ip, destination_ip])
    return f"{first}:{second}"


def get_flow_partition_key(flow_id: str) -> str:
    """Returns partition key for a specific flow ID."""
    return str(flow_id)


def get_entity_partition_key(entity_identifier: str) -> str:
    """Returns partition key for a network entity (e.g. source IP)."""
    return str(entity_identifier)


# Aliases for backward compatibility and registry access
TopicDefinition = TopicMetadata
SENTINEL_TOPICS = TOPIC_REGISTRY


def get_flow_raw_partition_key(flow: Any) -> str:
    """Returns deterministic partition key for FlowRecord."""
    return get_canonical_endpoint_key(flow.source_ip, flow.destination_ip)


def get_flow_feature_partition_key(flow_or_features: Any) -> str:
    """Returns partition key for FeatureVector or FlowRecord."""
    return str(flow_or_features.flow_id)


def get_detection_partition_key(detection: Any) -> str:
    """Returns partition key for DetectionResult."""
    return str(getattr(detection, "source_ip", None) or getattr(detection, "flow_id", "default"))


def get_alert_partition_key(alert: Any) -> str:
    """Returns partition key for SecurityAlert."""
    return str(
        getattr(alert, "correlation_group_id", None)
        or getattr(alert, "source_ip", None)
        or getattr(alert, "alert_id", "default")
    )


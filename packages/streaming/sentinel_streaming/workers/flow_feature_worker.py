"""Flow Feature Worker consuming raw network flows and emitting canonical feature vectors."""

import logging
from typing import Optional

from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector
from sentinel_streaming.bus import StreamConsumer, StreamProducer
from sentinel_streaming.reliability.deduplicator import generate_deterministic_event_id
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_FLOWS_FEATURES, TOPIC_FLOWS_RAW, get_flow_feature_partition_key
from sentinel_streaming.workers.base import BaseStreamWorker

logger = logging.getLogger(__name__)


class FlowFeatureWorker(BaseStreamWorker[FlowRecord, FeatureVector]):
    """Stream worker that extracts statistical, TCP, timing, and protocol features from raw flows."""

    def __init__(
        self,
        consumer: StreamConsumer,
        producer: StreamProducer,
        extractor: Optional[UnifiedFeatureExtractor] = None,
        input_topic: str = TOPIC_FLOWS_RAW,
        output_topic: str = TOPIC_FLOWS_FEATURES,
        **kwargs,
    ) -> None:
        super().__init__(
            consumer=consumer,
            producer=producer,
            model_class=FlowRecord,
            input_topic=input_topic,
            output_topic=output_topic,
            worker_name="FlowFeatureWorker",
            **kwargs,
        )
        self.extractor = extractor or UnifiedFeatureExtractor()

    def process_envelope(
        self, envelope: StreamEnvelope[FlowRecord]
    ) -> Optional[StreamEnvelope[FeatureVector]]:
        """Extract features from the FlowRecord and package into a new StreamEnvelope."""
        flow = envelope.payload
        features = self.extractor.extract(flow)

        # Retain original flow serialization in context for downstream detector access
        features.context["flow_record"] = flow.model_dump(mode="json")

        event_id = generate_deterministic_event_id(envelope.event_id, "feature_extraction")
        return StreamEnvelope(
            event_id=event_id,
            trace_id=envelope.trace_id,
            parent_event_id=envelope.event_id,
            schema_name="FeatureVector",
            schema_version="1.0",
            source_stage="feature_extraction",
            payload=features,
        )

    def get_output_partition_key(self, output_envelope: StreamEnvelope[FeatureVector]) -> Optional[str]:
        """Route to partition keyed by flow_id."""
        return get_flow_feature_partition_key(output_envelope.payload)

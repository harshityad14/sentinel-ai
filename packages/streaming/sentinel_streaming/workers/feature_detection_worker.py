"""Feature Detection Worker running hybrid threat detection against streaming feature vectors."""

import logging
from datetime import datetime, timezone
from typing import Optional

from sentinel_detection.pipeline import DetectionPipeline, create_default_detection_pipeline
from sentinel_models.detection import DetectionResult
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector
from sentinel_streaming.bus import StreamConsumer, StreamProducer
from sentinel_streaming.reliability.deduplicator import generate_deterministic_event_id
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_DETECTIONS_RAW, TOPIC_FLOWS_FEATURES, get_detection_partition_key
from sentinel_streaming.workers.base import BaseStreamWorker

logger = logging.getLogger(__name__)


class FeatureDetectionWorker(BaseStreamWorker[FeatureVector, DetectionResult]):
    """Stream worker analyzing incoming feature vectors using rule, statistical, and ML detectors."""

    def __init__(
        self,
        consumer: StreamConsumer,
        producer: StreamProducer,
        pipeline: Optional[DetectionPipeline] = None,
        input_topic: str = TOPIC_FLOWS_FEATURES,
        output_topic: str = TOPIC_DETECTIONS_RAW,
        **kwargs,
    ) -> None:
        super().__init__(
            consumer=consumer,
            producer=producer,
            model_class=FeatureVector,
            input_topic=input_topic,
            output_topic=output_topic,
            worker_name="FeatureDetectionWorker",
            **kwargs,
        )
        self.pipeline = pipeline or create_default_detection_pipeline()

    def process_envelope(
        self, envelope: StreamEnvelope[FeatureVector]
    ) -> Optional[StreamEnvelope[DetectionResult]]:
        """Run detection pipeline against feature vector and flow record.
        
        Returns a StreamEnvelope with DetectionResult if a threat was flagged, else None.
        """
        features = envelope.payload

        # Reconstruct FlowRecord from context if serialized by upstream worker
        flow = self._reconstruct_flow(features)

        detection = self.pipeline.analyze(flow, features)

        if not detection.is_threat:
            logger.debug(f"Flow {features.flow_id} evaluated as benign; skipping emission")
            return None

        event_id = generate_deterministic_event_id(envelope.event_id, "detection_analysis")
        return StreamEnvelope(
            event_id=event_id,
            trace_id=envelope.trace_id,
            parent_event_id=envelope.event_id,
            schema_name="DetectionResult",
            schema_version="1.0",
            source_stage="detection_engine",
            payload=detection,
        )

    def get_output_partition_key(self, output_envelope: StreamEnvelope[DetectionResult]) -> Optional[str]:
        """Route to partition keyed by source IP / primary entity."""
        return get_detection_partition_key(output_envelope.payload)

    def _reconstruct_flow(self, features: FeatureVector) -> FlowRecord:
        """Reconstruct FlowRecord from context payload or synthesize from features."""
        ctx = features.context or {}
        if "flow_record" in ctx and isinstance(ctx["flow_record"], dict):
            try:
                return FlowRecord.model_validate(ctx["flow_record"])
            except Exception as e:
                logger.warning(f"Failed to validate serialized flow_record from context: {e}")

        # Fallback reconstruction
        proto_str = str(ctx.get("protocol", "TCP")).upper()
        try:
            protocol = ProtocolType(proto_str)
        except ValueError:
            protocol = ProtocolType.TCP

        return FlowRecord(
            flow_id=features.flow_id,
            start_time=features.extraction_timestamp or datetime.now(timezone.utc),
            source_ip=ctx.get("source_ip", "127.0.0.1"),
            destination_ip=ctx.get("destination_ip", "127.0.0.1"),
            source_port=int(ctx.get("source_port", 0)),
            destination_port=int(ctx.get("destination_port", 0)),
            protocol=protocol,
            total_packets=features.network.total_packets,
            total_bytes=features.network.total_bytes,
            duration_sec=features.network.duration_sec,
            termination_reason="TIMEOUT",
        )

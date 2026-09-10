"""Detection Correlation Worker correlating detection signals into enriched security alerts."""

import logging
from typing import Optional

from sentinel_detection.correlation.correlator import AlertCorrelator
from sentinel_models.alerts import SecurityAlert
from sentinel_models.detection import DetectionResult
from sentinel_streaming.bus import StreamConsumer, StreamProducer
from sentinel_streaming.reliability.deduplicator import generate_deterministic_event_id
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_ALERTS_CORRELATED, TOPIC_DETECTIONS_RAW, get_alert_partition_key
from sentinel_streaming.workers.base import BaseStreamWorker

logger = logging.getLogger(__name__)


class DetectionCorrelationWorker(BaseStreamWorker[DetectionResult, SecurityAlert]):
    """Stream worker that aggregates individual DetectionResults into stateful SecurityAlerts."""

    def __init__(
        self,
        consumer: StreamConsumer,
        producer: StreamProducer,
        correlator: Optional[AlertCorrelator] = None,
        input_topic: str = TOPIC_DETECTIONS_RAW,
        output_topic: str = TOPIC_ALERTS_CORRELATED,
        **kwargs,
    ) -> None:
        super().__init__(
            consumer=consumer,
            producer=producer,
            model_class=DetectionResult,
            input_topic=input_topic,
            output_topic=output_topic,
            worker_name="DetectionCorrelationWorker",
            **kwargs,
        )
        self.correlator = correlator or AlertCorrelator()

    def process_envelope(
        self, envelope: StreamEnvelope[DetectionResult]
    ) -> Optional[StreamEnvelope[SecurityAlert]]:
        """Process detection result through temporal and heuristic correlation."""
        detection = envelope.payload

        alert, is_new = self.correlator.process_detection(detection)

        if alert is None:
            logger.debug(f"Detection {detection.detection_id} suppressed or no alert produced")
            return None

        event_id = generate_deterministic_event_id(envelope.event_id, "alert_correlation")
        return StreamEnvelope(
            event_id=event_id,
            trace_id=envelope.trace_id,
            parent_event_id=envelope.event_id,
            schema_name="SecurityAlert",
            schema_version="1.0",
            source_stage="correlation_engine",
            payload=alert,
        )

    def get_output_partition_key(self, output_envelope: StreamEnvelope[SecurityAlert]) -> Optional[str]:
        """Route to partition keyed by correlation group or entity ID."""
        return get_alert_partition_key(output_envelope.payload)

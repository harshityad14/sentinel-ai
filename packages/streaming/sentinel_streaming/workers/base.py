"""Base streaming worker providing lifecycle, reliability, deduplication, and offset control."""

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, Type, TypeVar

from sentinel_streaming.bus import StreamConsumer, StreamMessage, StreamProducer
from sentinel_streaming.reliability.dead_letter import build_dlq_envelope
from sentinel_streaming.reliability.deduplicator import IdempotencyDeduplicator
from sentinel_streaming.reliability.retry_handler import RetryHandler, is_retryable_exception
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_PIPELINE_DLQ

logger = logging.getLogger(__name__)

InT = TypeVar("InT")
OutT = TypeVar("OutT")


class BaseStreamWorker(ABC, Generic[InT, OutT]):
    """Abstract worker orchestrating consumption, processing, emission, and offset commitment."""

    def __init__(
        self,
        consumer: StreamConsumer,
        producer: Optional[StreamProducer] = None,
        model_class: Optional[Type[InT]] = None,
        input_topic: Optional[str] = None,
        output_topic: Optional[str] = None,
        dlq_topic: str = TOPIC_PIPELINE_DLQ,
        deduplicator: Optional[IdempotencyDeduplicator] = None,
        retry_handler: Optional[RetryHandler] = None,
        worker_name: Optional[str] = None,
    ) -> None:
        self.consumer = consumer
        self.producer = producer
        self.model_class = model_class
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.dlq_topic = dlq_topic
        self.deduplicator = deduplicator or IdempotencyDeduplicator()
        self.retry_handler = retry_handler or RetryHandler()
        self.worker_name = worker_name or self.__class__.__name__

        self._running = False
        self._stop_event = threading.Event()

        # Telemetry metrics
        self.processed_count: int = 0
        self.duplicate_count: int = 0
        self.failed_count: int = 0
        self.dlq_count: int = 0

    @property
    def is_running(self) -> bool:
        """Whether the worker event loop is active."""
        return self._running

    def start(self) -> None:
        """Subscribe consumer and prepare worker state."""
        if self.input_topic:
            self.consumer.subscribe([self.input_topic])
        self._running = True
        self._stop_event.clear()
        logger.info(f"Worker {self.worker_name} started on input topic: {self.input_topic}")

    def stop(self) -> None:
        """Signal worker to cleanly cease processing and flush pending state."""
        logger.info(f"Stopping worker {self.worker_name}...")
        self._running = False
        self._stop_event.set()
        if self.producer:
            self.producer.flush()
        self.consumer.close()
        logger.info(f"Worker {self.worker_name} stopped cleanly.")

    def run_poll_loop(self, poll_timeout: float = 1.0, max_messages: Optional[int] = None) -> int:
        """Synchronous poll loop running until stopped or max_messages reached.
        
        Returns total number of messages processed.
        """
        count = 0
        self.start()
        try:
            while self._running and not self._stop_event.is_set():
                msg = self.consumer.poll(timeout=poll_timeout)
                if msg is None:
                    continue

                self.process_message(msg)
                count += 1

                if max_messages is not None and count >= max_messages:
                    break
        finally:
            self.stop()
        return count

    def process_message(self, msg: StreamMessage) -> bool:
        """Process a single streaming message through deserialization, deduplication, handling, and commit.
        
        Returns True if processing succeeded or duplicate skipped; False on fatal error diverted to DLQ.
        """
        # 1. Parse into StreamEnvelope
        envelope: Optional[StreamEnvelope[InT]] = None
        try:
            envelope = StreamEnvelope.from_bytes(msg.value, payload_cls=self.model_class)
        except Exception as e:
            logger.error(f"{self.worker_name}: Malformed message on {msg.topic}: {e}")
            self._route_to_dlq(
                raw_payload=msg.value.decode("utf-8", errors="replace"),
                error_stage=self.worker_name,
                error=e,
                source_topic=msg.topic,
                source_partition=msg.partition,
                source_offset=msg.offset,
            )
            self.consumer.commit_sync()
            return False

        # 2. Deduplication check
        if self.deduplicator.is_duplicate(envelope.event_id):
            logger.debug(f"{self.worker_name}: Skipping duplicate event {envelope.event_id}")
            self.duplicate_count += 1
            self.consumer.commit_sync()
            return True

        # 3. Process payload with retry wrapper
        def operation():
            return self.process_envelope(envelope)

        try:
            output_envelope = self.retry_handler.execute(operation)
        except Exception as e:
            if is_retryable_exception(e):
                logger.error(f"{self.worker_name}: Retries exhausted for {envelope.event_id}: {e}")
            else:
                logger.error(f"{self.worker_name}: Fatal non-retryable error for {envelope.event_id}: {e}")

            self._route_to_dlq(
                raw_payload=msg.value.decode("utf-8", errors="replace"),
                error_stage=self.worker_name,
                error=e,
                source_topic=msg.topic,
                source_partition=msg.partition,
                source_offset=msg.offset,
                trace_id=envelope.trace_id,
            )
            self.failed_count += 1
            self.consumer.commit_sync()
            return False

        # 4. Emit downstream if produced
        if output_envelope is not None and self.producer and self.output_topic:
            key = self.get_output_partition_key(output_envelope)
            self.producer.produce(
                topic=self.output_topic,
                value=output_envelope.to_bytes(),
                key=key,
            )
            # Strict ordering: flush before committing consumer offset
            self.producer.flush()

        # 5. Mark as processed in deduplicator and commit offset
        self.deduplicator.record_processed(envelope.event_id)
        self.consumer.commit_sync()
        self.processed_count += 1
        return True

    @abstractmethod
    def process_envelope(self, envelope: StreamEnvelope[InT]) -> Optional[StreamEnvelope[OutT]]:
        """Core domain processing logic to be implemented by specialized workers."""
        raise NotImplementedError

    def get_output_partition_key(self, output_envelope: StreamEnvelope[OutT]) -> Optional[str]:
        """Derive the partition key for downstream message routing. Override in subclasses."""
        return None

    def _route_to_dlq(
        self,
        raw_payload: str,
        error_stage: str,
        error: Exception,
        source_topic: str,
        source_partition: int,
        source_offset: int,
        trace_id: Optional[str] = None,
    ) -> None:
        """Route unprocessable messages to the Dead-Letter Queue preserving trace and offset diagnostics."""
        self.dlq_count += 1
        if not self.producer:
            return

        dlq_env = build_dlq_envelope(
            raw_payload=raw_payload,
            error_stage=error_stage,
            error=error,
            source_topic=source_topic,
            source_partition=source_partition,
            source_offset=source_offset,
            trace_id=trace_id,
        )
        try:
            self.producer.produce(
                topic=self.dlq_topic,
                value=dlq_env.to_bytes(),
                key=dlq_env.trace_id,
            )
            self.producer.flush()
        except Exception as dlq_err:
            logger.critical(f"{self.worker_name}: Failed to emit message to DLQ: {dlq_err}")

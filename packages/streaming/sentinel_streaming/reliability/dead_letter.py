"""Dead-letter queue (DLQ) envelope formatting and error diversion."""

import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from sentinel_streaming.schemas import StreamEnvelope


class DeadLetterEnvelope(BaseModel):
    """Metadata payload stored in the dead-letter queue topic for forensic triage."""

    error_stage: str = Field(default="unknown_stage", description="Worker or stage where fault occurred")
    source_topic: str = Field(default="", description="Originating topic where failure occurred")
    source_partition: Optional[int] = Field(default=None, description="Partition of failing message")
    source_offset: Optional[int] = Field(default=None, description="Offset of failing message")
    trace_id: Optional[str] = Field(default=None, description="Trace ID if decodable")
    original_event_id: Optional[str] = Field(default=None, description="Event ID of failing message if decodable")
    exception_class: str = Field(default="", description="Python exception class name")
    error_message: str = Field(default="", description="Exception text description")
    stack_trace: str = Field(default="", description="Full traceback string")
    attempt_count: int = Field(default=1, description="Number of execution attempts prior to DLQ diversion")
    failed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp of DLQ diversion",
    )
    raw_payload: Optional[str] = Field(
        default=None,
        description="Raw string or encoded byte representation if unparsable",
    )
    unparsed_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Deserialized dictionary payload if parsed but failed downstream processing",
    )

    def to_bytes(self) -> bytes:
        """Serialize DLQ envelope to bytes."""
        return self.model_dump_json().encode("utf-8")


def build_dlq_envelope(
    raw_payload: Optional[str] = None,
    error_stage: str = "unknown_stage",
    error: Optional[Exception] = None,
    exc: Optional[Exception] = None,
    source_topic: str = "",
    original_topic: Optional[str] = None,
    source_partition: Optional[int] = None,
    original_partition: Optional[int] = None,
    source_offset: Optional[int] = None,
    original_offset: Optional[int] = None,
    original_event_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    attempt_count: int = 1,
    unparsed_payload: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> DeadLetterEnvelope:
    """Build a DeadLetterEnvelope for safe DLQ transmission."""
    exception_obj = error or exc
    exc_class = exception_obj.__class__.__name__ if exception_obj else kwargs.get("exception_class", "UnknownError")
    exc_msg = str(exception_obj) if exception_obj else kwargs.get("exception_message", "")
    tb_str = traceback.format_exc() if exception_obj else ""

    topic = source_topic or original_topic or ""
    partition = source_partition if source_partition is not None else original_partition
    offset = source_offset if source_offset is not None else original_offset

    return DeadLetterEnvelope(
        error_stage=error_stage,
        source_topic=topic,
        source_partition=partition,
        source_offset=offset,
        trace_id=trace_id,
        original_event_id=original_event_id,
        exception_class=exc_class,
        error_message=exc_msg,
        stack_trace=tb_str,
        attempt_count=attempt_count,
        raw_payload=raw_payload,
        unparsed_payload=unparsed_payload,
    )

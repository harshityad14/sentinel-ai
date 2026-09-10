"""Streaming message envelope and schema serialization."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Generic, Optional, Type, TypeVar
from pydantic import BaseModel, Field, model_validator

T = TypeVar("T")


class StreamingSchemaError(Exception):
    """Base exception for envelope schema and serialization failures."""
    pass


class MalformedEnvelopeError(StreamingSchemaError):
    """Raised when envelope payload cannot be decoded as valid JSON or envelope structure."""
    pass


class UnsupportedSchemaVersionError(StreamingSchemaError):
    """Raised when envelope schema major version is incompatible with current worker."""
    def __init__(self, current_version: str, received_version: str):
        super().__init__(f"Incompatible schema version received: {received_version} (expected: {current_version})")
        self.current_version = current_version
        self.received_version = received_version


class StreamEnvelope(BaseModel, Generic[T]):
    """Standardized metadata envelope container for all streaming pipeline events."""

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this specific message event",
    )
    trace_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Causal trace ID linking all downstream pipeline derivatives",
    )
    parent_event_id: Optional[str] = Field(
        default=None,
        description="Event ID of the immediate causal upstream event",
    )
    source_stage: Optional[str] = Field(
        default=None,
        description="Pipeline stage or worker that generated this event",
    )
    source_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp when event was first observed",
    )
    published_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp when event was published to streaming bus",
    )
    schema_name: Optional[str] = Field(
        default=None,
        description="Name of the underlying schema model",
    )
    schema_version: str = Field(
        default="1.0.0",
        description="Semantic schema version (MAJOR.MINOR.PATCH)",
    )
    payload_type: str = Field(
        default="",
        description="Discriminator identifier for payload domain model class",
    )
    payload: T = Field(
        description="Domain payload data (dict or model instance)",
    )

    @model_validator(mode="before")
    @classmethod
    def set_payload_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            payload = data.get("payload")
            if not data.get("payload_type"):
                if payload is not None and hasattr(payload, "__class__"):
                    data["payload_type"] = payload.__class__.__name__
                elif data.get("schema_name"):
                    data["payload_type"] = data["schema_name"]
                else:
                    data["payload_type"] = "dict"
            if not data.get("schema_name"):
                data["schema_name"] = data.get("payload_type", "Unknown")
        return data

    def to_bytes(self) -> bytes:
        """Serialize envelope to UTF-8 JSON bytes."""
        return serialize_envelope(self)

    @classmethod
    def from_bytes(
        cls,
        raw_bytes: bytes,
        payload_cls: Optional[Type[T]] = None,
        expected_major_version: int = 1,
    ) -> "StreamEnvelope[T]":
        """Deserialize UTF-8 bytes into StreamEnvelope with schema validation."""
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise MalformedEnvelopeError(f"Failed to decode message as JSON: {exc}") from exc

        if not isinstance(data, dict) or "payload" not in data or "schema_version" not in data:
            raise MalformedEnvelopeError("Missing required envelope fields ('payload', 'schema_version')")

        received_version = str(data["schema_version"])
        try:
            received_major = int(received_version.split(".")[0])
        except (ValueError, IndexError):
            received_major = 1

        if received_major != expected_major_version:
            raise ValueError(
                f"Incompatible schema major version: received {received_version}, expected {expected_major_version}"
            )

        payload_val = data["payload"]
        if payload_cls is not None and isinstance(payload_val, dict):
            if hasattr(payload_cls, "model_validate"):
                data["payload"] = payload_cls.model_validate(payload_val)
            else:
                data["payload"] = payload_cls(**payload_val)

        return cls(**data)


def serialize_envelope(envelope: StreamEnvelope) -> bytes:
    """Serialize a StreamEnvelope to UTF-8 encoded JSON bytes."""
    return envelope.model_dump_json().encode("utf-8")


def deserialize_envelope(raw_bytes: bytes, target_version: str = "1.0.0") -> StreamEnvelope[Dict[str, Any]]:
    """Deserialize UTF-8 bytes into a StreamEnvelope with strict version validation."""
    expected_major = int(target_version.split(".")[0])
    return StreamEnvelope.from_bytes(raw_bytes, payload_cls=None, expected_major_version=expected_major)

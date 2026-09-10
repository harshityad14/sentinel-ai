"""Performance telemetry and pipeline measurement contracts."""

from datetime import datetime
from pydantic import BaseModel, Field


class IngestionMetrics(BaseModel):
    """Packet ingestion throughput performance measurements."""
    packets_ingested_total: int = Field(default=0, ge=0)
    bytes_ingested_total: int = Field(default=0, ge=0)
    ingestion_throughput_pps: float = Field(
        default=0.0, ge=0.0, description="Current packet ingestion throughput in packets/sec"
    )
    window_duration_sec: float = Field(default=1.0, gt=0.0)


class FlowMetrics(BaseModel):
    """Flow engine processing throughput performance measurements."""
    flows_active_count: int = Field(default=0, ge=0)
    flows_completed_total: int = Field(default=0, ge=0)
    flow_throughput_fps: float = Field(
        default=0.0, ge=0.0, description="Current flow processing throughput in flows/sec"
    )


class DetectionLatencyMetrics(BaseModel):
    """End-to-end detection latency telemetry."""
    avg_latency_ms: float = Field(
        default=0.0, ge=0.0, description="Average end-to-end detection latency in milliseconds"
    )
    p95_latency_ms: float = Field(
        default=0.0, ge=0.0, description="95th percentile detection latency in milliseconds"
    )
    p99_latency_ms: float = Field(
        default=0.0, ge=0.0, description="99th percentile detection latency in milliseconds"
    )
    max_latency_ms: float = Field(
        default=0.0, ge=0.0, description="Maximum observed detection latency in milliseconds"
    )


class TelemetrySnapshot(BaseModel):
    """Unified telemetry snapshot capturing the three core performance benchmarks."""
    timestamp: datetime = Field(..., description="Timestamp of telemetry collection")
    ingestion: IngestionMetrics = Field(default_factory=IngestionMetrics)
    flows: FlowMetrics = Field(default_factory=FlowMetrics)
    detection_latency: DetectionLatencyMetrics = Field(default_factory=DetectionLatencyMetrics)

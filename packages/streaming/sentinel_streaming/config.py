"""Streaming configuration settings."""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class StreamingConfig(BaseSettings):
    """Configuration settings for Kafka producers, consumers, and workers."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bootstrap_servers: str = Field(
        default="localhost:9092",
        alias="KAFKA_BOOTSTRAP_SERVERS",
        description="Kafka broker connection endpoints",
    )
    client_id: str = Field(default="sentinel-streaming", alias="KAFKA_CLIENT_ID")
    group_id_prefix: str = Field(default="sentinel-cg", alias="KAFKA_GROUP_ID_PREFIX")

    # Consumer options
    auto_offset_reset: str = Field(default="earliest", alias="KAFKA_AUTO_OFFSET_RESET")
    enable_auto_commit: bool = Field(default=False, alias="KAFKA_ENABLE_AUTO_COMMIT")
    max_poll_records: int = Field(default=500, alias="KAFKA_MAX_POLL_RECORDS")
    poll_timeout_ms: int = Field(default=1000, alias="KAFKA_POLL_TIMEOUT_MS")

    # Producer options
    linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    compression_type: str = Field(default="lz4", alias="KAFKA_COMPRESSION_TYPE")
    queue_buffering_max_messages: int = Field(default=100000, alias="KAFKA_QUEUE_MAX_MESSAGES")

    # Reliability and DLQ
    max_retries: int = Field(default=3, alias="STREAMING_MAX_RETRIES")
    retry_base_backoff_ms: int = Field(default=100, alias="STREAMING_RETRY_BASE_MS")
    retry_max_backoff_ms: int = Field(default=2000, alias="STREAMING_RETRY_MAX_MS")
    dlq_topic: str = Field(default="sentinel.pipeline.dlq", alias="STREAMING_DLQ_TOPIC")

    # Idempotency and deduplication
    dedup_window_sec: int = Field(default=300, alias="STREAMING_DEDUP_WINDOW_SEC")
    dedup_cache_size: int = Field(default=50000, alias="STREAMING_DEDUP_CACHE_SIZE")


default_streaming_config = StreamingConfig()

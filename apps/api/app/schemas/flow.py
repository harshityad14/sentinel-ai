"""Flow and Feature API schemas."""

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class FlowRead(BaseModel):
    """Network flow record response schema."""

    model_config = ConfigDict(from_attributes=True)

    flow_id: str = Field(description="Unique flow identifier")
    start_time: datetime = Field(description="Flow start timestamp")
    end_time: datetime = Field(description="Flow end timestamp")
    duration: float = Field(description="Flow duration in seconds")
    src_ip: str = Field(description="Source IP address")
    dst_ip: str = Field(description="Destination IP address")
    src_port: int = Field(description="Source transport port")
    dst_port: int = Field(description="Destination transport port")
    protocol: str = Field(description="Transport protocol (e.g. TCP, UDP)")
    packet_count: int = Field(description="Total packet count")
    byte_count: int = Field(description="Total byte count")
    packets_fwd: int = Field(description="Forward packets count")
    packets_bwd: int = Field(description="Backward packets count")
    bytes_fwd: int = Field(description="Forward bytes count")
    bytes_bwd: int = Field(description="Backward bytes count")
    is_bidirectional: bool = Field(description="Whether flow saw traffic in both directions")
    created_at: datetime = Field(description="Record ingestion timestamp")


class FlowFeatureRead(BaseModel):
    """Flow feature vector response schema."""

    model_config = ConfigDict(from_attributes=True)

    flow_id: str = Field(description="Associated flow ID")
    timestamp: datetime = Field(description="Feature calculation timestamp")
    features: Dict[str, Any] = Field(description="Extracted feature payload")
    status: str = Field(description="Feature extraction status")
    created_at: datetime = Field(description="Record creation timestamp")

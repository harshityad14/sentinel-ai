"""Canonical typed feature models for SentinelAI detection pipeline."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field


class FeatureDataType(str, Enum):
    FLOAT = "float"
    INTEGER = "int"
    BOOLEAN = "bool"
    STRING = "str"


class FeatureStatus(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PLANNED = "PLANNED"


class NetworkFeatures(BaseModel):
    """Network-level volumetric and rate features derived from FlowRecord."""
    duration_sec: float = Field(ge=0.0, description="Flow duration in seconds")
    total_packets: int = Field(ge=0, description="Total packet count in both directions")
    total_bytes: int = Field(ge=0, description="Total byte count in both directions")
    forward_packets: int = Field(ge=0, description="Packets sent by originator")
    backward_packets: int = Field(ge=0, description="Packets sent by responder")
    forward_bytes: int = Field(ge=0, description="Bytes sent by originator")
    backward_bytes: int = Field(ge=0, description="Bytes sent by responder")
    
    # Rates
    packets_per_second: float = Field(ge=0.0, description="Total packets per second")
    bytes_per_second: float = Field(ge=0.0, description="Total bytes per second")
    forward_packets_per_second: float = Field(ge=0.0, description="Originator packets per second")
    backward_packets_per_second: float = Field(ge=0.0, description="Responder packets per second")
    
    # Asymmetric volume ratios
    forward_backward_packet_ratio: float = Field(ge=0.0, description="Forward / Backward packet ratio")
    forward_backward_byte_ratio: float = Field(ge=0.0, description="Forward / Backward byte ratio")
    byte_asymmetry_ratio: float = Field(
        ge=0.0, le=1.0, description="Forward bytes / Total bytes (0.0 to 1.0)"
    )
    
    # Packet size distribution
    mean_packet_size: float = Field(ge=0.0, description="Arithmetic mean packet size in bytes")
    min_packet_size: int = Field(ge=0, description="Minimum packet wire length")
    max_packet_size: int = Field(ge=0, description="Maximum packet wire length")
    packet_size_std: float = Field(ge=0.0, description="Packet size standard deviation")


class TCPFeatures(BaseModel):
    """Passive TCP flag and handshake behavioral features."""
    syn_count: int = Field(ge=0)
    ack_count: int = Field(ge=0)
    fin_count: int = Field(ge=0)
    rst_count: int = Field(ge=0)
    psh_count: int = Field(ge=0)
    urg_count: int = Field(ge=0)
    ece_count: int = Field(ge=0)
    cwr_count: int = Field(ge=0)
    
    # Ratios
    syn_ack_ratio: float = Field(ge=0.0, description="SYN / ACK ratio")
    rst_ratio: float = Field(ge=0.0, le=1.0, description="RST packets / Total packets")
    fin_ratio: float = Field(ge=0.0, le=1.0, description="FIN packets / Total packets")


class TimingFeatures(BaseModel):
    """Passive timing and inter-packet arrival features."""
    mean_inter_arrival_sec: float = Field(
        ge=0.0, description="Average time between consecutive packets"
    )
    min_inter_arrival_sec: Optional[float] = Field(
        default=None, ge=0.0, description="Minimum inter-packet arrival time"
    )
    max_inter_arrival_sec: Optional[float] = Field(
        default=None, ge=0.0, description="Maximum inter-packet arrival time"
    )
    inter_arrival_std_sec: Optional[float] = Field(
        default=None, ge=0.0, description="Standard deviation of inter-arrival times"
    )
    jitter_ratio: Optional[float] = Field(
        default=None, ge=0.0, description="Inter-arrival standard deviation / mean"
    )
    burst_count: Optional[int] = Field(
        default=None, ge=0, description="Count of detected traffic bursts"
    )


class DNSFeatures(BaseModel):
    """Passive unencrypted DNS query telemetry features."""
    query_length: int = Field(ge=0, description="Total length of query name string")
    subdomain_depth: int = Field(ge=0, description="Number of subdomain labels")
    shannon_entropy: float = Field(ge=0.0, description="Shannon entropy of query string (bits/char)")
    digit_ratio: float = Field(ge=0.0, le=1.0, description="Digits / total query length")
    alphabetic_ratio: float = Field(ge=0.0, le=1.0, description="Alphabetic chars / total length")
    unique_char_ratio: float = Field(ge=0.0, le=1.0, description="Unique characters / total length")
    label_count: int = Field(ge=0, description="Count of dot-delimited domain labels")
    is_nxdomain: bool = Field(default=False, description="Whether DNS query returned NXDOMAIN")


class TLSFeatures(BaseModel):
    """Passive unencrypted TLS handshake telemetry features."""
    tls_version: Optional[str] = Field(default=None, description="Advertised TLS version string")
    sni_present: bool = Field(default=False, description="Whether SNI was included in ClientHello")
    cipher_suite_count: int = Field(default=0, ge=0, description="Number of offered cipher suites")
    ja3_present: bool = Field(default=False, description="Whether JA3 fingerprint was calculated")
    ja3_hash: Optional[str] = Field(default=None, description="JA3 MD5 client fingerprint")
    ja4_present: bool = Field(default=False, description="Whether JA4 fingerprint was calculated")
    ja4_hash: Optional[str] = Field(default=None, description="JA4 client fingerprint")


class FeatureVector(BaseModel):
    """Canonical strongly-typed security feature vector emitted for detection models."""
    flow_id: str = Field(..., description="Source FlowRecord flow identifier")
    feature_version: str = Field(default="1.0", description="Feature specification schema version")
    extraction_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when feature extraction occurred",
    )
    
    # Feature category groups (Explicit None when metadata was unavailable)
    network: NetworkFeatures
    tcp: Optional[TCPFeatures] = None
    timing: TimingFeatures
    dns: Optional[DNSFeatures] = None
    tls: Optional[TLSFeatures] = None

    # Contextual metadata (non-features for routing and logging)
    context: Dict[str, Any] = Field(default_factory=dict)

    def to_flat_dict(self) -> Dict[str, Optional[Union[float, int, str, bool]]]:
        """Flatten feature categories into a flat dictionary suitable for tabular ML models."""
        flat: Dict[str, Optional[Union[float, int, str, bool]]] = {}

        # 1. Network features
        for k, v in self.network.model_dump().items():
            flat[f"net_{k}"] = v

        # 2. TCP features
        if self.tcp is not None:
            for k, v in self.tcp.model_dump().items():
                flat[f"tcp_{k}"] = v
        else:
            for k in TCPFeatures.model_fields.keys():
                flat[f"tcp_{k}"] = None

        # 3. Timing features
        for k, v in self.timing.model_dump().items():
            flat[f"time_{k}"] = v

        # 4. DNS features
        if self.dns is not None:
            for k, v in self.dns.model_dump().items():
                flat[f"dns_{k}"] = v
        else:
            for k in DNSFeatures.model_fields.keys():
                flat[f"dns_{k}"] = None

        # 5. TLS features
        if self.tls is not None:
            for k, v in self.tls.model_dump().items():
                flat[f"tls_{k}"] = v
        else:
            for k in TLSFeatures.model_fields.keys():
                flat[f"tls_{k}"] = None

        return flat

    def to_json(self) -> str:
        """Deterministic JSON representation."""
        return self.model_dump_json(indent=2)

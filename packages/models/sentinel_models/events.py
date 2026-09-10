"""Domain event models for passive network traffic observation."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class TCPFlags(BaseModel):
    """Decoded TCP flag bitmask."""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False


class DNSMetadata(BaseModel):
    """Unencrypted DNS query and response telemetry."""
    query_name: str = Field(..., description="Fully qualified domain name queried")
    query_type: str = Field(..., description="DNS record type, e.g., A, AAAA, TXT, MX")
    response_code: Optional[str] = Field(default=None, description="DNS RCODE, e.g., NOERROR, NXDOMAIN")
    answers: List[str] = Field(default_factory=list, description="Answer records returned")
    subdomain_count: int = Field(default=0, description="Count of subdomain labels")
    domain_length: int = Field(default=0, description="Length of domain name string")


class TLSMetadata(BaseModel):
    """Unencrypted TLS handshake parameters and fingerprints."""
    sni: Optional[str] = Field(default=None, description="Server Name Indication from ClientHello")
    version: Optional[str] = Field(default=None, description="Advertised TLS protocol version")
    cipher_suites: List[str] = Field(default_factory=list, description="List of cipher suites in client order")
    extensions: List[int] = Field(default_factory=list, description="Offered TLS extension IDs")
    ja3: Optional[str] = Field(default=None, description="Computed JA3 client fingerprint hash")
    ja4: Optional[str] = Field(default=None, description="Computed JA4 client fingerprint string")


class PacketMetadata(BaseModel):
    """Canonical representation of an individual passively captured packet."""
    timestamp: datetime = Field(..., description="Timestamp of packet capture")
    source_ip: str = Field(..., description="Source IPv4 or IPv6 address")
    destination_ip: str = Field(..., description="Destination IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Source L4 port")
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination L4 port")
    protocol: ProtocolType = Field(..., description="Transport protocol")
    packet_length: int = Field(..., ge=0, description="Total wire packet length in bytes")
    payload_length: int = Field(default=0, ge=0, description="L4 payload length in bytes")
    tcp_flags: Optional[TCPFlags] = Field(default=None, description="Decoded TCP flags if protocol is TCP")
    dns: Optional[DNSMetadata] = Field(default=None, description="Decoded DNS metadata if observed")
    tls: Optional[TLSMetadata] = Field(default=None, description="Decoded TLS handshake if observed")


class FlowRecord(BaseModel):
    """Stateful bi-directional 5-tuple network flow session."""
    flow_id: str = Field(..., description="Canonical deterministic flow identifier")
    start_time: datetime = Field(..., description="Timestamp of the first observed packet")
    last_seen_time: datetime = Field(..., description="Timestamp of the most recent packet")
    duration_sec: float = Field(default=0.0, ge=0.0, description="Total flow duration in seconds")
    
    # 5-tuple endpoint parameters
    source_ip: str = Field(...)
    destination_ip: str = Field(...)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: ProtocolType = Field(...)
    
    # Bi-directional volumetric metrics
    forward_packets: int = Field(default=0, ge=0, description="Packets sent by originator")
    backward_packets: int = Field(default=0, ge=0, description="Packets sent by responder")
    forward_bytes: int = Field(default=0, ge=0, description="Bytes sent by originator")
    backward_bytes: int = Field(default=0, ge=0, description="Bytes sent by responder")
    
    # Connection state
    is_active: bool = Field(default=True, description="Whether the flow is currently active")
    termination_reason: Optional[str] = Field(default=None, description="Timeout, FIN, RST, or active flush")
    
    # Handshake context
    dns_context: Optional[DNSMetadata] = None
    tls_context: Optional[TLSMetadata] = None
    
    # Statistical feature payload (populated in Phase 2)
    features: Dict[str, Any] = Field(default_factory=dict, description="Extracted feature vector")

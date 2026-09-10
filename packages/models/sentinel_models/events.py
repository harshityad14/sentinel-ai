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
    last_seen_time: Optional[datetime] = Field(default=None, description="Timestamp of the most recent packet")
    end_time: Optional[datetime] = Field(default=None, description="Timestamp of the last observed packet")
    duration_sec: float = Field(default=0.0, ge=0.0, description="Total flow duration in seconds")
    
    # 5-tuple endpoint parameters
    source_ip: str = Field(...)
    destination_ip: str = Field(...)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: ProtocolType = Field(...)
    
    # Volumetric metrics
    total_packets: int = Field(default=0, ge=0, description="Total packet count in both directions")
    forward_packets: int = Field(default=0, ge=0, description="Packets sent by originator")
    backward_packets: int = Field(default=0, ge=0, description="Packets sent by responder")
    total_bytes: int = Field(default=0, ge=0, description="Total byte count in both directions")
    forward_bytes: int = Field(default=0, ge=0, description="Bytes sent by originator")
    backward_bytes: int = Field(default=0, ge=0, description="Bytes sent by responder")

    # Packet size distribution statistics
    min_packet_size: int = Field(default=0, ge=0, description="Minimum packet wire length in bytes")
    max_packet_size: int = Field(default=0, ge=0, description="Maximum packet wire length in bytes")
    mean_packet_size: float = Field(default=0.0, ge=0.0, description="Mean packet wire length in bytes")
    std_packet_size: float = Field(default=0.0, ge=0.0, description="Packet size standard deviation")

    # TCP flag counters
    tcp_flags: Dict[str, int] = Field(
        default_factory=dict, description="Aggregated counts of TCP flags observed (syn, ack, fin, rst, etc.)"
    )
    
    # Connection state
    is_active: bool = Field(default=True, description="Whether the flow is currently active")
    termination_reason: Optional[str] = Field(default=None, description="Timeout, FIN, RST, or active flush")
    
    # Handshake context
    dns_context: Optional[DNSMetadata] = None
    tls_context: Optional[TLSMetadata] = None
    
    # Statistical feature payload (populated in Phase 2)
    features: Dict[str, Any] = Field(default_factory=dict, description="Extracted feature vector")

    def model_post_init(self, __context: Any) -> None:
        """Synchronize last_seen_time and end_time, and totals if not explicitly provided."""
        if self.end_time is None and self.last_seen_time is not None:
            self.end_time = self.last_seen_time
        elif self.last_seen_time is None and self.end_time is not None:
            self.last_seen_time = self.end_time
        elif self.end_time is None and self.last_seen_time is None:
            self.end_time = self.start_time
            self.last_seen_time = self.start_time

        if self.total_packets == 0 and (self.forward_packets > 0 or self.backward_packets > 0):
            self.total_packets = self.forward_packets + self.backward_packets
        if self.total_bytes == 0 and (self.forward_bytes > 0 or self.backward_bytes > 0):
            self.total_bytes = self.forward_bytes + self.backward_bytes

    def to_jsonl(self) -> str:
        """Serialize FlowRecord to a deterministic, single-line JSON string."""
        return self.model_dump_json()

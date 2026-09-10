"""Centralized Feature Registry and Versioning for SentinelAI."""

from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from sentinel_models.features import FeatureDataType, FeatureStatus


class FeatureDefinition(BaseModel):
    """Metadata definition for an individual engineered security feature."""
    name: str = Field(..., description="Unique canonical feature identifier")
    description: str = Field(..., description="Technical explanation of the feature")
    data_type: FeatureDataType = Field(..., description="Feature scalar data type")
    category: str = Field(..., description="Functional group: network, tcp, timing, dns, tls")
    version: str = Field(default="1.0", description="Feature schema version")
    status: FeatureStatus = Field(default=FeatureStatus.IMPLEMENTED, description="Implementation status")


class FeatureRegistry:
    """Registry maintaining definitions and versions for all platform security features."""

    def __init__(self) -> None:
        # Key: (name, version)
        self._registry: Dict[Tuple[str, str], FeatureDefinition] = {}
        self._load_defaults()

    def register(self, feature: FeatureDefinition) -> None:
        """Register a feature definition. Raises ValueError if already registered."""
        key = (feature.name, feature.version)
        if key in self._registry:
            raise ValueError(f"Feature '{feature.name}' version '{feature.version}' is already registered.")
        self._registry[key] = feature

    def get(self, name: str, version: str = "1.0") -> Optional[FeatureDefinition]:
        """Retrieve a registered feature definition by name and version."""
        return self._registry.get((name, version))

    def list_features(
        self,
        category: Optional[str] = None,
        version: Optional[str] = None,
        status: Optional[FeatureStatus] = None,
    ) -> List[FeatureDefinition]:
        """List registered features with optional filtering."""
        results: List[FeatureDefinition] = []
        for (f_name, f_ver), f_def in self._registry.items():
            if category and f_def.category.lower() != category.lower():
                continue
            if version and f_ver != version:
                continue
            if status and f_def.status != status:
                continue
            results.append(f_def)
        return sorted(results, key=lambda f: (f.category, f.name))

    def _load_defaults(self) -> None:
        """Populate initial canonical '1.0' feature catalog."""
        default_features = [
            # Network Volumetric & Rate Features
            FeatureDefinition(name="duration_sec", description="Flow duration in seconds", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="total_packets", description="Total packets in both directions", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="total_bytes", description="Total bytes in both directions", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="forward_packets", description="Packets sent by originator", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="backward_packets", description="Packets sent by responder", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="forward_bytes", description="Bytes sent by originator", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="backward_bytes", description="Bytes sent by responder", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="packets_per_second", description="Packet rate (packets/sec)", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="bytes_per_second", description="Byte transfer rate (bytes/sec)", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="forward_packets_per_second", description="Originator packet rate", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="backward_packets_per_second", description="Responder packet rate", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="forward_backward_packet_ratio", description="Forward/backward packet ratio", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="forward_backward_byte_ratio", description="Forward/backward byte ratio", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="byte_asymmetry_ratio", description="Forward bytes / Total bytes", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="mean_packet_size", description="Mean packet size in bytes", data_type=FeatureDataType.FLOAT, category="network"),
            FeatureDefinition(name="min_packet_size", description="Minimum packet length in bytes", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="max_packet_size", description="Maximum packet length in bytes", data_type=FeatureDataType.INTEGER, category="network"),
            FeatureDefinition(name="packet_size_std", description="Standard deviation of packet sizes", data_type=FeatureDataType.FLOAT, category="network"),

            # TCP Flags & Ratios
            FeatureDefinition(name="syn_count", description="TCP SYN flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="ack_count", description="TCP ACK flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="fin_count", description="TCP FIN flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="rst_count", description="TCP RST flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="psh_count", description="TCP PSH flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="urg_count", description="TCP URG flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="ece_count", description="TCP ECE flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="cwr_count", description="TCP CWR flag occurrences", data_type=FeatureDataType.INTEGER, category="tcp"),
            FeatureDefinition(name="syn_ack_ratio", description="SYN to ACK packet ratio", data_type=FeatureDataType.FLOAT, category="tcp"),
            FeatureDefinition(name="rst_ratio", description="RST packets to total packets ratio", data_type=FeatureDataType.FLOAT, category="tcp"),
            FeatureDefinition(name="fin_ratio", description="FIN packets to total packets ratio", data_type=FeatureDataType.FLOAT, category="tcp"),

            # Timing & Inter-Arrival Dynamics
            FeatureDefinition(name="mean_inter_arrival_sec", description="Average inter-packet arrival time", data_type=FeatureDataType.FLOAT, category="timing"),
            FeatureDefinition(name="min_inter_arrival_sec", description="Minimum inter-packet arrival time", data_type=FeatureDataType.FLOAT, category="timing"),
            FeatureDefinition(name="max_inter_arrival_sec", description="Maximum inter-packet arrival time", data_type=FeatureDataType.FLOAT, category="timing"),
            FeatureDefinition(name="inter_arrival_std_sec", description="Inter-arrival standard deviation", data_type=FeatureDataType.FLOAT, category="timing"),
            FeatureDefinition(name="jitter_ratio", description="Timing jitter ratio (std/mean)", data_type=FeatureDataType.FLOAT, category="timing"),
            FeatureDefinition(name="burst_count", description="Detected traffic bursts count", data_type=FeatureDataType.INTEGER, category="timing"),

            # Planned Sequence Timing Features
            FeatureDefinition(name="splt_sequence", description="Sequence of Packet Lengths and Times", data_type=FeatureDataType.STRING, category="timing", status=FeatureStatus.PLANNED),

            # DNS Query Characteristics
            FeatureDefinition(name="query_length", description="Total length of DNS query domain", data_type=FeatureDataType.INTEGER, category="dns"),
            FeatureDefinition(name="subdomain_depth", description="Number of subdomain labels", data_type=FeatureDataType.INTEGER, category="dns"),
            FeatureDefinition(name="shannon_entropy", description="Shannon entropy of query string", data_type=FeatureDataType.FLOAT, category="dns"),
            FeatureDefinition(name="digit_ratio", description="Ratio of digits to total characters", data_type=FeatureDataType.FLOAT, category="dns"),
            FeatureDefinition(name="alphabetic_ratio", description="Ratio of alphabetic characters", data_type=FeatureDataType.FLOAT, category="dns"),
            FeatureDefinition(name="unique_char_ratio", description="Ratio of distinct characters", data_type=FeatureDataType.FLOAT, category="dns"),
            FeatureDefinition(name="label_count", description="Count of domain labels", data_type=FeatureDataType.INTEGER, category="dns"),
            FeatureDefinition(name="is_nxdomain", description="NXDOMAIN status flag", data_type=FeatureDataType.BOOLEAN, category="dns"),

            # TLS Telemetry
            FeatureDefinition(name="tls_version", description="Negotiated TLS protocol version", data_type=FeatureDataType.STRING, category="tls"),
            FeatureDefinition(name="sni_present", description="Server Name Indication presence", data_type=FeatureDataType.BOOLEAN, category="tls"),
            FeatureDefinition(name="cipher_suite_count", description="Count of advertised cipher suites", data_type=FeatureDataType.INTEGER, category="tls"),
            FeatureDefinition(name="ja3_present", description="JA3 client fingerprint presence", data_type=FeatureDataType.BOOLEAN, category="tls"),
            FeatureDefinition(name="ja3_hash", description="JA3 MD5 client fingerprint hash", data_type=FeatureDataType.STRING, category="tls"),
            FeatureDefinition(name="ja4_present", description="JA4 client fingerprint presence", data_type=FeatureDataType.BOOLEAN, category="tls"),
            FeatureDefinition(name="ja4_hash", description="JA4 client fingerprint string", data_type=FeatureDataType.STRING, category="tls"),
        ]

        for feat in default_features:
            self.register(feat)


# Global default registry instance
default_registry = FeatureRegistry()

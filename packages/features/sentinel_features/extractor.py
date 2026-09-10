"""Unified feature extraction coordinator for SentinelAI."""

from typing import Any, Dict, Optional, Sequence

from sentinel_features.base import BaseFeatureExtractor
from sentinel_features.dns import DNSFeatureExtractor
from sentinel_features.network import NetworkFeatureExtractor
from sentinel_features.registry import FeatureRegistry, default_registry
from sentinel_features.tcp import TCPFeatureExtractor
from sentinel_features.tls import TLSFeatureExtractor
from sentinel_features.timing import TimingFeatureExtractor
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class UnifiedFeatureExtractor(BaseFeatureExtractor):
    """Coordinates specialized feature extractors to produce canonical FeatureVector objects."""

    def __init__(self, registry: Optional[FeatureRegistry] = None, version: str = "1.0") -> None:
        self.registry = registry or default_registry
        self.version = version

    def extract(
        self,
        flow: FlowRecord,
        packet_timestamps: Optional[Sequence[float]] = None,
    ) -> FeatureVector:
        """Extract all feature groups from a FlowRecord and return a typed FeatureVector.
        
        Args:
            flow: FlowRecord instance to analyze.
            packet_timestamps: Optional list of epoch timestamps for individual packets in the flow.
        """
        # 1. Network features (always present)
        net_feats = NetworkFeatureExtractor.extract(flow)

        # 2. TCP features (None if not TCP or no flags)
        tcp_feats = TCPFeatureExtractor.extract(flow)

        # 3. Timing features (computes aggregate or sequence if provided)
        time_feats = TimingFeatureExtractor.extract(flow, packet_timestamps=packet_timestamps)

        # 4. DNS features (None if no DNS metadata)
        dns_feats = DNSFeatureExtractor.extract(flow.dns_context)

        # 5. TLS features (None if no TLS metadata)
        tls_feats = TLSFeatureExtractor.extract(flow.tls_context)

        # 6. Context metadata (for routing, alerts, and human triage)
        ctx = {
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol.value,
            "termination_reason": flow.termination_reason,
        }

        vector = FeatureVector(
            flow_id=flow.flow_id,
            feature_version=self.version,
            network=net_feats,
            tcp=tcp_feats,
            timing=time_feats,
            dns=dns_feats,
            tls=tls_feats,
            context=ctx,
        )

        # Populate in-memory flow features map as well
        flow.features = vector.to_flat_dict()

        return vector

    def extract_features(self, flow: FlowRecord) -> Dict[str, Any]:
        """Implement BaseFeatureExtractor interface by returning flattened feature map."""
        return self.extract(flow).to_flat_dict()

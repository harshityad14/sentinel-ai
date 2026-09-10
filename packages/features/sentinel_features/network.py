"""Network volumetric and rate feature extraction from FlowRecord."""

from sentinel_features.statistical import rate, ratio, safe_div
from sentinel_models.events import FlowRecord
from sentinel_models.features import NetworkFeatures


class NetworkFeatureExtractor:
    """Extracts volumetric, rate, and asymmetric ratio features from a FlowRecord."""

    @staticmethod
    def extract(flow: FlowRecord) -> NetworkFeatures:
        """Derive NetworkFeatures from FlowRecord without inspecting payloads."""
        duration = max(0.0, flow.duration_sec)
        tot_pkts = max(0, flow.total_packets)
        tot_bytes = max(0, flow.total_bytes)
        fwd_pkts = max(0, flow.forward_packets)
        bwd_pkts = max(0, flow.backward_packets)
        fwd_bytes = max(0, flow.forward_bytes)
        bwd_bytes = max(0, flow.backward_bytes)

        # Rates (packets/sec and bytes/sec)
        pps = round(rate(tot_pkts, duration), 4)
        bps = round(rate(tot_bytes, duration), 4)
        fwd_pps = round(rate(fwd_pkts, duration), 4)
        bwd_pps = round(rate(bwd_pkts, duration), 4)

        # Asymmetry and direction ratios
        fwd_bwd_pkt_ratio = round(ratio(fwd_pkts, bwd_pkts), 4)
        fwd_bwd_byte_ratio = round(ratio(fwd_bytes, bwd_bytes), 4)
        byte_asym_ratio = round(safe_div(fwd_bytes, tot_bytes, default=0.5), 4)

        return NetworkFeatures(
            duration_sec=round(duration, 6),
            total_packets=tot_pkts,
            total_bytes=tot_bytes,
            forward_packets=fwd_pkts,
            backward_packets=bwd_pkts,
            forward_bytes=fwd_bytes,
            backward_bytes=bwd_bytes,
            packets_per_second=pps,
            bytes_per_second=bps,
            forward_packets_per_second=fwd_pps,
            backward_packets_per_second=bwd_pps,
            forward_backward_packet_ratio=fwd_bwd_pkt_ratio,
            forward_backward_byte_ratio=fwd_bwd_byte_ratio,
            byte_asymmetry_ratio=byte_asym_ratio,
            mean_packet_size=round(flow.mean_packet_size, 4),
            min_packet_size=flow.min_packet_size,
            max_packet_size=flow.max_packet_size,
            packet_size_std=round(flow.std_packet_size, 4),
        )

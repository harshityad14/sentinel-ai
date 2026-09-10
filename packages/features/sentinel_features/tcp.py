"""Passive TCP behavioral feature extraction from FlowRecord."""

from typing import Optional
from sentinel_features.statistical import ratio, safe_div
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import TCPFeatures


class TCPFeatureExtractor:
    """Extracts passive TCP flag metrics and ratios from FlowRecord."""

    @staticmethod
    def extract(flow: FlowRecord) -> Optional[TCPFeatures]:
        """Derive TCPFeatures from FlowRecord.
        
        Returns None if flow is non-TCP or has no TCP flag metadata.
        """
        if flow.protocol != ProtocolType.TCP or not flow.tcp_flags:
            return None

        flags = flow.tcp_flags
        syn = max(0, flags.get("syn", 0))
        ack = max(0, flags.get("ack", 0))
        fin = max(0, flags.get("fin", 0))
        rst = max(0, flags.get("rst", 0))
        psh = max(0, flags.get("psh", 0))
        urg = max(0, flags.get("urg", 0))
        ece = max(0, flags.get("ece", 0))
        cwr = max(0, flags.get("cwr", 0))

        tot_pkts = max(1, flow.total_packets)

        syn_ack_r = round(ratio(syn, ack), 4)
        rst_r = round(safe_div(rst, tot_pkts), 4)
        fin_r = round(safe_div(fin, tot_pkts), 4)

        return TCPFeatures(
            syn_count=syn,
            ack_count=ack,
            fin_count=fin,
            rst_count=rst,
            psh_count=psh,
            urg_count=urg,
            ece_count=ece,
            cwr_count=cwr,
            syn_ack_ratio=syn_ack_r,
            rst_ratio=rst_r,
            fin_ratio=fin_r,
        )

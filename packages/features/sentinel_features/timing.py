"""Passive timing and inter-packet arrival feature extraction."""

from typing import Optional, Sequence
from sentinel_features.statistical import safe_div, summary_statistics
from sentinel_models.events import FlowRecord
from sentinel_models.features import TimingFeatures


class TimingFeatureExtractor:
    """Extracts timing, inter-arrival, and burstiness features from FlowRecord and packet intervals."""

    @staticmethod
    def extract(
        flow: FlowRecord,
        packet_timestamps: Optional[Sequence[float]] = None,
    ) -> TimingFeatures:
        """Derive TimingFeatures.
        
        Args:
            flow: FlowRecord representing the session.
            packet_timestamps: Optional sequence of epoch timestamps for individual packets
                              (used when packet-level temporal sequences are captured).
        """
        tot_pkts = max(0, flow.total_packets)
        duration = max(0.0, flow.duration_sec)

        # Baseline aggregate mean inter-arrival time
        if tot_pkts > 1:
            agg_mean_iat = round(safe_div(duration, tot_pkts - 1), 6)
        else:
            agg_mean_iat = 0.0

        # Detailed sequence analysis if individual timestamps are available
        if packet_timestamps and len(packet_timestamps) > 1:
            intervals = [
                max(0.0, packet_timestamps[i] - packet_timestamps[i - 1])
                for i in range(1, len(packet_timestamps))
            ]
            min_iat, max_iat, mean_iat, std_iat = summary_statistics(intervals)
            jitter_r = round(safe_div(std_iat, mean_iat), 4)

            # Burst detection: count inter-arrivals significantly smaller than mean (< 0.2 * mean)
            burst_threshold = 0.2 * mean_iat
            bursts = sum(1 for delta in intervals if delta < burst_threshold)

            return TimingFeatures(
                mean_inter_arrival_sec=round(mean_iat, 6),
                min_inter_arrival_sec=round(min_iat, 6),
                max_inter_arrival_sec=round(max_iat, 6),
                inter_arrival_std_sec=round(std_iat, 6),
                jitter_ratio=jitter_r,
                burst_count=bursts,
            )

        # If packet timestamp sequence is not available, provide aggregate and explicit None
        return TimingFeatures(
            mean_inter_arrival_sec=agg_mean_iat,
            min_inter_arrival_sec=None,
            max_inter_arrival_sec=None,
            inter_arrival_std_sec=None,
            jitter_ratio=None,
            burst_count=None,
        )

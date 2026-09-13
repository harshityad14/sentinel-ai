"""Dataset adapters mapping public benchmark datasets to authoritative SentinelAI FeatureVectors.

Translates raw CSV telemetry from:
- CIC-IDS2017 / CSE-CIC-IDS2018 / CIC-DDoS2019
- UNSW-NB15
into the authoritative 15-feature CANONICAL_ML_FEATURES schema.

IMPORTANT: Strictly passive feature mapping. No payload inspection or decryption.
"""

import math
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_models.detection import ThreatType


class BaseDatasetAdapter(ABC):
    """Abstract interface for mapping third-party network datasets to SentinelAI features."""

    @property
    def canonical_features(self) -> List[str]:
        return CANONICAL_ML_FEATURES

    @abstractmethod
    def adapt_record(self, record: Dict[str, Any]) -> Optional[Tuple[List[float], str]]:
        """Normalize a single raw record into (feature_vector, mapped_label).
        
        Returns None if record contains invalid, unrecoverable data or unsupported labels.
        """
        raise NotImplementedError


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert value to finite float or default."""
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    """Convert value to int or default."""
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return int(f)
    except (ValueError, TypeError):
        return default


class CICDatasetAdapter(BaseDatasetAdapter):
    """Adapter for Canadian Institute for Cybersecurity datasets (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019)."""

    # Explicit label mapping from CIC attack categories to SentinelAI ThreatType
    LABEL_MAPPING: Dict[str, str] = {
        # Normal baseline
        "benign": ThreatType.BENIGN.value,
        # Port scan / reconnaissance
        "portscan": ThreatType.PORT_SCAN.value,
        # Volumetric SYN flood / transport DoS
        "dos hulk": ThreatType.SYN_FLOOD.value,
        "dos goldeneye": ThreatType.SYN_FLOOD.value,
        "dos slowloris": ThreatType.SYN_FLOOD.value,
        "dos slowhttptest": ThreatType.SYN_FLOOD.value,
        "syn": ThreatType.SYN_FLOOD.value,
        "syn flood": ThreatType.SYN_FLOOD.value,
        # Volumetric UDP flood
        "ddos": ThreatType.UDP_FLOOD.value,
        "udp": ThreatType.UDP_FLOOD.value,
        "udp-lag": ThreatType.UDP_FLOOD.value,
        "udp flood": ThreatType.UDP_FLOOD.value,
        # Botnet / C2 beaconing
        "bot": ThreatType.C2_BEACONING.value,
        "ares": ThreatType.C2_BEACONING.value,
        # Infiltration / Data Exfiltration
        "infiltration": ThreatType.DATA_EXFILTRATION.value,
        # Web and brute force behavioral anomalies
        "ftp-patator": ThreatType.BEHAVIORAL_ANOMALY.value,
        "ssh-patator": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \x96 brute force": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack - brute force": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \ufffd brute force": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \x96 xss": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack - xss": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \ufffd xss": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \x96 sql injection": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack - sql injection": ThreatType.BEHAVIORAL_ANOMALY.value,
        "web attack \ufffd sql injection": ThreatType.BEHAVIORAL_ANOMALY.value,
        "heartbleed": ThreatType.BEHAVIORAL_ANOMALY.value,
    }

    # Classes explicitly unsupported because L7 payload/DNS metadata is absent in NetFlow
    UNSUPPORTED_CLASSES: Set[str] = {
        ThreatType.DNS_DGA.value,
        ThreatType.DNS_TUNNELING.value,
        ThreatType.SUSPICIOUS_TLS.value,
    }

    def adapt_record(self, record: Dict[str, Any]) -> Optional[Tuple[List[float], str]]:
        # Normalize keys (strip whitespace, lower)
        norm_row = {k.strip().lower(): v for k, v in record.items()}

        # 1. Label extraction & normalization
        raw_label = norm_row.get("label", norm_row.get("labels", ""))
        label_key = str(raw_label).strip().lower()
        mapped_label = self.LABEL_MAPPING.get(label_key)
        if not mapped_label:
            return None

        # 2. Extract raw columns
        # Note: CIC datasets record Flow Duration in microseconds!
        duration_us = _safe_float(norm_row.get("flow duration", norm_row.get("flow_duration", 0.0)))
        duration_sec = max(0.0, duration_us / 1_000_000.0)

        fwd_pkts = max(0, _safe_int(norm_row.get("total fwd packets", norm_row.get("total_fwd_packets", 0))))
        bwd_pkts = max(0, _safe_int(norm_row.get("total backward packets", norm_row.get("total_backward_packets", 0))))
        total_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = max(0, _safe_float(norm_row.get("total length of fwd packets", norm_row.get("total_length_of_fwd_packets", 0.0))))
        bwd_bytes = max(0, _safe_float(norm_row.get("total length of bwd packets", norm_row.get("total_length_of_bwd_packets", 0.0))))
        total_bytes = fwd_bytes + bwd_bytes

        # Rates
        bytes_per_sec = _safe_float(norm_row.get("flow bytes/s", norm_row.get("flow_bytes/s", 0.0)))
        if bytes_per_sec <= 0.0 and duration_sec > 0:
            bytes_per_sec = total_bytes / duration_sec

        pkts_per_sec = _safe_float(norm_row.get("flow packets/s", norm_row.get("flow_packets/s", 0.0)))
        if pkts_per_sec <= 0.0 and duration_sec > 0:
            pkts_per_sec = total_pkts / duration_sec

        # Byte asymmetry ratio (forward bytes / total bytes)
        byte_asymmetry = fwd_bytes / total_bytes if total_bytes > 0 else 0.5
        byte_asymmetry = min(1.0, max(0.0, byte_asymmetry))

        # Packet sizes
        mean_pkt_size = _safe_float(norm_row.get("average packet size", norm_row.get("packet length mean", 0.0)))
        if mean_pkt_size <= 0.0 and total_pkts > 0:
            mean_pkt_size = total_bytes / total_pkts

        pkt_size_std = _safe_float(norm_row.get("packet length std", 0.0))

        # Timing (Flow IAT Mean and Std in microseconds!)
        iat_mean_us = _safe_float(norm_row.get("flow iat mean", 0.0))
        time_mean_iat = max(0.0, iat_mean_us / 1_000_000.0)
        if time_mean_iat <= 0.0 and total_pkts > 1 and duration_sec > 0:
            time_mean_iat = duration_sec / (total_pkts - 1)

        iat_std_us = _safe_float(norm_row.get("flow iat std", 0.0))
        time_iat_std = max(0.0, iat_std_us / 1_000_000.0)

        # Jitter ratio
        jitter_ratio = (time_iat_std / time_mean_iat) if time_mean_iat > 1e-6 else 0.0
        jitter_ratio = min(100.0, max(0.0, jitter_ratio))

        # Assemble strictly in CANONICAL_ML_FEATURES order
        feature_vector = [
            round(duration_sec, 6),
            round(total_bytes, 2),
            round(fwd_bytes, 2),
            round(bwd_bytes, 2),
            float(total_pkts),
            float(fwd_pkts),
            float(bwd_pkts),
            round(bytes_per_sec, 4),
            round(pkts_per_sec, 4),
            round(byte_asymmetry, 4),
            round(mean_pkt_size, 4),
            round(pkt_size_std, 4),
            round(time_mean_iat, 6),
            round(time_iat_std, 6),
            round(jitter_ratio, 4),
        ]

        return feature_vector, mapped_label


class UNSWDatasetAdapter(BaseDatasetAdapter):
    """Adapter for UNSW-NB15 dataset used for external cross-environment validation."""

    LABEL_MAPPING: Dict[str, str] = {
        "normal": ThreatType.BENIGN.value,
        "reconnaissance": ThreatType.PORT_SCAN.value,
        "backdoor": ThreatType.C2_BEACONING.value,
        "backdoors": ThreatType.C2_BEACONING.value,
        "dos": ThreatType.SYN_FLOOD.value,
        "fuzzers": ThreatType.BEHAVIORAL_ANOMALY.value,
        "exploits": ThreatType.BEHAVIORAL_ANOMALY.value,
        "generic": ThreatType.BEHAVIORAL_ANOMALY.value,
        "analysis": ThreatType.BEHAVIORAL_ANOMALY.value,
        "worms": ThreatType.BEHAVIORAL_ANOMALY.value,
    }

    def adapt_record(self, record: Dict[str, Any]) -> Optional[Tuple[List[float], str]]:
        norm_row = {k.strip().lower(): v for k, v in record.items()}

        # Label extraction
        raw_label = norm_row.get("attack_cat", norm_row.get("label", ""))
        label_key = str(raw_label).strip().lower()
        if label_key in ("0", "0.0"):
            label_key = "normal"
        mapped_label = self.LABEL_MAPPING.get(label_key)
        if not mapped_label:
            return None

        # Duration in seconds
        duration_sec = max(0.0, _safe_float(norm_row.get("dur", 0.0)))

        fwd_pkts = max(0, _safe_int(norm_row.get("spkts", 0)))
        bwd_pkts = max(0, _safe_int(norm_row.get("dpkts", 0)))
        total_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = max(0, _safe_float(norm_row.get("sbytes", 0.0)))
        bwd_bytes = max(0, _safe_float(norm_row.get("dbytes", 0.0)))
        total_bytes = fwd_bytes + bwd_bytes

        # Rates
        pkts_per_sec = _safe_float(norm_row.get("rate", 0.0))
        if pkts_per_sec <= 0.0 and duration_sec > 0:
            pkts_per_sec = total_pkts / duration_sec

        bytes_per_sec = total_bytes / max(0.001, duration_sec)

        # Byte asymmetry
        byte_asymmetry = fwd_bytes / total_bytes if total_bytes > 0 else 0.5
        byte_asymmetry = min(1.0, max(0.0, byte_asymmetry))

        # Packet sizes
        mean_pkt_size = total_bytes / max(1, total_pkts)
        pkt_size_std = 0.0  # Not in UNSW summary, imputed neutrally

        # Timing (sinpkt, dinpkt in milliseconds in UNSW-NB15)
        sinpkt_ms = _safe_float(norm_row.get("sinpkt", 0.0))
        dinpkt_ms = _safe_float(norm_row.get("dinpkt", 0.0))
        if sinpkt_ms > 0 and dinpkt_ms > 0:
            time_mean_iat = ((sinpkt_ms + dinpkt_ms) / 2.0) / 1000.0
        elif total_pkts > 1 and duration_sec > 0:
            time_mean_iat = duration_sec / (total_pkts - 1)
        else:
            time_mean_iat = 0.0

        time_iat_std = 0.0  # Imputed neutrally
        jitter_ratio = 0.0  # Imputed neutrally

        feature_vector = [
            round(duration_sec, 6),
            round(total_bytes, 2),
            round(fwd_bytes, 2),
            round(bwd_bytes, 2),
            float(total_pkts),
            float(fwd_pkts),
            float(bwd_pkts),
            round(bytes_per_sec, 4),
            round(pkts_per_sec, 4),
            round(byte_asymmetry, 4),
            round(mean_pkt_size, 4),
            round(pkt_size_std, 4),
            round(time_mean_iat, 6),
            round(time_iat_std, 6),
            round(jitter_ratio, 4),
        ]

        return feature_vector, mapped_label

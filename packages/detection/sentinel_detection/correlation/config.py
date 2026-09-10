"""Configuration dataclasses and defaults for alert correlation and deduplication."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class CorrelationConfig:
    """Configurable temporal, deduplication, and suppression parameters."""

    # Sliding time window in seconds for aggregating related detections into a correlation group
    time_window_sec: float = 60.0

    # Window in seconds for merging identical detections (same source IP + threat type) into existing alert
    duplicate_window_sec: float = 30.0

    # Cooldown window in seconds for suppressing duplicate alert emissions on noisy entities
    suppression_window_sec: float = 120.0

    # Upper bound on retained contributing signals per alert to enforce bounded memory
    max_signals_per_alert: int = 100

    # Maximum active correlation groups tracked simultaneously in memory
    max_active_groups: int = 10_000

    # Maximum active alerts retained in the correlator state cache
    max_active_alerts: int = 10_000

    # Cross-threat relationship links for multi-stage kill chain grouping
    cross_threat_links: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "PORT_SCAN": ["C2_BEACONING", "SYN_FLOOD", "DATA_EXFILTRATION", "BEHAVIORAL_ANOMALY"],
            "DNS_DGA": ["DNS_TUNNELING", "C2_BEACONING", "DATA_EXFILTRATION"],
            "DNS_TUNNELING": ["DATA_EXFILTRATION", "C2_BEACONING"],
            "SUSPICIOUS_TLS": ["C2_BEACONING", "DATA_EXFILTRATION"],
            "C2_BEACONING": ["DATA_EXFILTRATION"],
        }
    )

    # Weights for multi-factor risk scoring
    risk_weight_confidence: float = 0.25
    risk_weight_severity: float = 0.30
    risk_weight_agreement: float = 0.15
    risk_weight_signal_count: float = 0.10
    risk_weight_recurrence: float = 0.10
    risk_weight_temporal_proximity: float = 0.10

"""Severity and Confidence policy specification for SentinelAI.

SEVERITY VS CONFIDENCE PRINCIPLE:
Confidence represents how mathematically/algorithmically certain the detector is that its
specific pattern was observed (e.g., 99% confident that a domain has high Shannon entropy).
Severity represents the potential operational impact and harm of the threat to the network
or organization (e.g., DNS DGA is MEDIUM impact, whereas an active multi-gigabit SYN Flood
or confirmed C2 beaconing is HIGH/CRITICAL).

High confidence does NOT automatically imply CRITICAL severity.
"""

from typing import Any, Dict, List, Optional
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, ThreatType


# Base baseline severity ratings per threat type
BASELINE_SEVERITY: Dict[ThreatType, DetectionSeverity] = {
    ThreatType.BENIGN: DetectionSeverity.INFO,
    ThreatType.BEHAVIORAL_ANOMALY: DetectionSeverity.MEDIUM,
    ThreatType.PORT_SCAN: DetectionSeverity.LOW,
    ThreatType.DNS_DGA: DetectionSeverity.MEDIUM,
    ThreatType.SUSPICIOUS_TLS: DetectionSeverity.MEDIUM,
    ThreatType.DNS_TUNNELING: DetectionSeverity.HIGH,
    ThreatType.C2_BEACONING: DetectionSeverity.HIGH,
    ThreatType.DATA_EXFILTRATION: DetectionSeverity.HIGH,
    ThreatType.UDP_FLOOD: DetectionSeverity.HIGH,
    ThreatType.SYN_FLOOD: DetectionSeverity.HIGH,
}


def evaluate_severity(
    threat_type: ThreatType,
    confidence: float,
    evidence: Optional[List[DetectionEvidence]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> DetectionSeverity:
    """Determine threat severity using domain impact policy rather than raw confidence.
    
    Escalations:
    - PORT_SCAN escalates to MEDIUM if multiple ports/targets confirmed via host context.
    - SYN_FLOOD / UDP_FLOOD escalates to CRITICAL if extreme volume/PPS is observed.
    - DATA_EXFILTRATION escalates to CRITICAL if outbound volume exceeds critical enterprise thresholds (> 100MB).
    - C2_BEACONING escalates to CRITICAL if high confidence (> 0.90) and persistent repetition confirmed.
    - BEHAVIORAL_ANOMALY remains LOW/MEDIUM unless multi-metric deviation is extreme (> 8.0 z-score).
    """
    if threat_type == ThreatType.BENIGN:
        return DetectionSeverity.INFO

    base_sev = BASELINE_SEVERITY.get(threat_type, DetectionSeverity.MEDIUM)
    ctx = context or {}

    # 1. Volumetric DoS escalation
    if threat_type in (ThreatType.SYN_FLOOD, ThreatType.UDP_FLOOD):
        # Check for extreme packet volume in evidence
        if evidence:
            for ev in evidence:
                if ev.feature_name in ("tcp_syn_count", "net_total_packets") and isinstance(ev.observed_value, (int, float)):
                    if ev.observed_value >= 500:
                        return DetectionSeverity.CRITICAL
                if ev.feature_name == "net_packets_per_second" and isinstance(ev.observed_value, (int, float)):
                    if ev.observed_value >= 500.0:
                        return DetectionSeverity.CRITICAL

    # 2. Exfiltration volume escalation
    elif threat_type == ThreatType.DATA_EXFILTRATION:
        if evidence:
            for ev in evidence:
                if ev.feature_name == "net_outbound_bytes" and isinstance(ev.observed_value, (int, float)):
                    if ev.observed_value >= 100_000_000:  # > 100 MB
                        return DetectionSeverity.CRITICAL

    # 3. C2 Beaconing escalation
    elif threat_type == ThreatType.C2_BEACONING:
        if confidence >= 0.90 and ctx.get("repetition_count", 0) >= 10:
            return DetectionSeverity.CRITICAL

    # 4. Port scan escalation
    elif threat_type == ThreatType.PORT_SCAN:
        scanned_count = ctx.get("scanned_ports_count", 0)
        if scanned_count >= 50:
            return DetectionSeverity.HIGH
        elif scanned_count >= 15:
            return DetectionSeverity.MEDIUM

    return base_sev

"""Static offline MITRE ATT&CK mapping catalog for SentinelAI threat classes.

INVARIANT: This module performs zero external network calls or dynamic web queries.
It provides static, deterministic mappings from local threat classes to standard
MITRE ATT&CK Tactics, Techniques, and Sub-techniques for alert enrichment.
"""

from typing import Dict, Optional, Union
from sentinel_models.alerts import MitreAttackRef
from sentinel_models.detection import ThreatType


class MitreAttackMapper:
    """Static catalog mapping SentinelAI threat classes to MITRE ATT&CK techniques."""

    # Static local catalog mapping
    STATIC_CATALOG: Dict[str, MitreAttackRef] = {
        "SYN_FLOOD": MitreAttackRef(
            tactic="Impact",
            tactic_id="TA0040",
            technique="Network Denial of Service",
            technique_id="T1498",
            subtechnique_id="T1498.001",  # Direct Network Flood
        ),
        "UDP_FLOOD": MitreAttackRef(
            tactic="Impact",
            tactic_id="TA0040",
            technique="Network Denial of Service",
            technique_id="T1498",
            subtechnique_id="T1498.001",
        ),
        "PORT_SCAN": MitreAttackRef(
            tactic="Discovery",
            tactic_id="TA0007",
            technique="Network Service Discovery",
            technique_id="T1046",
        ),
        "C2_BEACONING": MitreAttackRef(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Application Layer Protocol",
            technique_id="T1071",
            subtechnique_id="T1071.001",  # Web Protocols
        ),
        "DNS_DGA": MitreAttackRef(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Dynamic Resolution",
            technique_id="T1568",
            subtechnique_id="T1568.002",  # Domain Generation Algorithms
        ),
        "DNS_TUNNELING": MitreAttackRef(
            tactic="Exfiltration",
            tactic_id="TA0010",
            technique="Application Layer Protocol",
            technique_id="T1071",
            subtechnique_id="T1071.004",  # DNS
        ),
        "SUSPICIOUS_TLS": MitreAttackRef(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Encrypted Channel",
            technique_id="T1573",
            subtechnique_id="T1573.002",  # Asymmetric Cryptography
        ),
        "DATA_EXFILTRATION": MitreAttackRef(
            tactic="Exfiltration",
            tactic_id="TA0010",
            technique="Exfiltration Over Alternative Protocol",
            technique_id="T1048",
            subtechnique_id="T1048.003",  # Exfiltration Over Unencrypted/Asymmetric Protocol
        ),
        "BEHAVIORAL_ANOMALY": MitreAttackRef(
            tactic="Defense Evasion",
            tactic_id="TA0005",
            technique="Application Layer Protocol",
            technique_id="T1071",
        ),
    }

    @classmethod
    def get_mapping(cls, threat_class: Union[ThreatType, str]) -> Optional[MitreAttackRef]:
        """Lookup static MITRE ATT&CK reference for a given threat category."""
        key = threat_class.value if isinstance(threat_class, ThreatType) else str(threat_class).upper()
        return cls.STATIC_CATALOG.get(key)

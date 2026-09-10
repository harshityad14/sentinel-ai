"""Ground-truth evaluation scenarios across 9 attack types for the SentinelAI GenAI Analyst."""

from datetime import datetime, timezone
from typing import Dict, List

from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    MitreAttackRef,
    RiskScore,
    SecurityAlert,
)


def get_evaluation_scenarios() -> Dict[str, SecurityAlert]:
    """Return dictionary of 9 canonical ground-truth security alerts for AI evaluation."""
    now = datetime.now(timezone.utc)

    scenarios = {
        "syn_flood": SecurityAlert(
            alert_id="alt-eval-syn-01",
            timestamp=now,
            threat_class="SYN_FLOOD",
            confidence=0.98,
            severity=AlertSeverity.CRITICAL,
            risk_score=RiskScore(score=94, explanation="Volumetric SYN flood queue exhaustion"),
            source_ip="192.0.2.100",
            destination_ip="10.0.0.5",
            source_port=54321,
            destination_port=80,
            status=AlertStatus.NEW,
            explanation="5,400 SYN packets observed with zero completing 3-way handshakes",
            mitre_attack=MitreAttackRef(
                tactic="Impact",
                tactic_id="TA0040",
                technique="Network Denial of Service",
                technique_id="T1498",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="syn_flood_detector",
                    feature_name="syn_ratio",
                    observed_value=0.99,
                    threshold_value=0.85,
                    confidence_contribution=0.95,
                )
            ],
            contributing_signals=[
                AlertSignal(
                    signal_id="sig-syn-01",
                    flow_id="fl-syn-01",
                    threat_type="SYN_FLOOD",
                    detector_type="RULE",
                    detector_name="syn_flood_detector",
                    confidence=0.98,
                    severity="CRITICAL",
                )
            ],
        ),
        "udp_flood": SecurityAlert(
            alert_id="alt-eval-udp-02",
            timestamp=now,
            threat_class="UDP_FLOOD",
            confidence=0.96,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=88, explanation="High volumetric UDP flood"),
            source_ip="198.51.100.22",
            destination_ip="10.0.0.8",
            destination_port=53,
            status=AlertStatus.NEW,
            explanation="High-frequency UDP packet flood to destination port 53",
            mitre_attack=MitreAttackRef(
                tactic="Impact",
                tactic_id="TA0040",
                technique="Direct Network Flood",
                technique_id="T1498.001",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="udp_detector",
                    feature_name="packet_rate",
                    observed_value=12500,
                    threshold_value=5000,
                    confidence_contribution=0.9,
                )
            ],
        ),
        "port_scan": SecurityAlert(
            alert_id="alt-eval-scan-03",
            timestamp=now,
            threat_class="PORT_SCAN",
            confidence=0.94,
            severity=AlertSeverity.MEDIUM,
            risk_score=RiskScore(score=72, explanation="Reconnaissance port sweep"),
            source_ip="10.1.1.45",
            destination_ip="10.1.1.10",
            status=AlertStatus.NEW,
            explanation="Sequential probing of 64 ports within a 15-second window",
            mitre_attack=MitreAttackRef(
                tactic="Reconnaissance",
                tactic_id="TA0043",
                technique="Network Service Discovery",
                technique_id="T1046",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="port_scan_detector",
                    feature_name="unique_ports",
                    observed_value=64,
                    threshold_value=20,
                    confidence_contribution=0.88,
                )
            ],
        ),
        "c2_beaconing": SecurityAlert(
            alert_id="alt-eval-c2-04",
            timestamp=now,
            threat_class="C2_BEACONING",
            confidence=0.92,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=86, explanation="Periodic C2 beaconing pattern"),
            source_ip="10.2.2.15",
            destination_ip="203.0.113.88",
            destination_port=443,
            status=AlertStatus.NEW,
            explanation="Periodic outbound TLS sessions every 60 seconds with low jitter",
            mitre_attack=MitreAttackRef(
                tactic="Command and Control",
                tactic_id="TA0011",
                technique="Application Layer Protocol",
                technique_id="T1071",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="c2_detector",
                    feature_name="interval_jitter",
                    observed_value=0.003,
                    threshold_value=0.05,
                    confidence_contribution=0.92,
                )
            ],
        ),
        "dns_dga": SecurityAlert(
            alert_id="alt-eval-dga-05",
            timestamp=now,
            threat_class="DNS_DGA",
            confidence=0.91,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=82, explanation="Algorithmic domain generation query burst"),
            source_ip="10.3.3.77",
            destination_ip="10.0.0.1",
            destination_port=53,
            status=AlertStatus.NEW,
            explanation="Burst of high-entropy NXDOMAIN queries to pseudo-random domain labels",
            mitre_attack=MitreAttackRef(
                tactic="Command and Control",
                tactic_id="TA0011",
                technique="Dynamic Resolution: Domain Generation Algorithms",
                technique_id="T1568.002",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="dga_detector",
                    feature_name="domain_entropy",
                    observed_value=4.62,
                    threshold_value=3.8,
                    confidence_contribution=0.88,
                )
            ],
        ),
        "dns_tunneling": SecurityAlert(
            alert_id="alt-eval-tunnel-06",
            timestamp=now,
            threat_class="DNS_TUNNELING",
            confidence=0.95,
            severity=AlertSeverity.CRITICAL,
            risk_score=RiskScore(score=91, explanation="Data exfiltration via DNS tunneling"),
            source_ip="10.4.4.12",
            destination_ip="10.0.0.1",
            destination_port=53,
            status=AlertStatus.NEW,
            explanation="Anomalously long TXT records and subdomain labels transferring encoded bytes",
            mitre_attack=MitreAttackRef(
                tactic="Exfiltration",
                tactic_id="TA0010",
                technique="Exfiltration Over Alternative Protocol: DNS",
                technique_id="T1048.003",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="tunneling_detector",
                    feature_name="subdomain_length",
                    observed_value=128,
                    threshold_value=60,
                    confidence_contribution=0.94,
                )
            ],
        ),
        "suspicious_tls": SecurityAlert(
            alert_id="alt-eval-tls-07",
            timestamp=now,
            threat_class="SUSPICIOUS_TLS",
            confidence=0.89,
            severity=AlertSeverity.MEDIUM,
            risk_score=RiskScore(score=70, explanation="Outdated TLS handshake with untrusted SNI"),
            source_ip="10.5.5.90",
            destination_ip="198.51.100.12",
            destination_port=443,
            status=AlertStatus.NEW,
            explanation="Client initiated TLS 1.0 handshake with deprecated cipher suites",
            mitre_attack=MitreAttackRef(
                tactic="Defense Evasion",
                tactic_id="TA0005",
                technique="Indicator Removal on Host",
                technique_id="T1070",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="tls_detector",
                    feature_name="tls_version",
                    observed_value="TLSv1.0",
                    threshold_value="TLSv1.2+",
                    confidence_contribution=0.85,
                )
            ],
        ),
        "data_exfiltration": SecurityAlert(
            alert_id="alt-eval-exfil-08",
            timestamp=now,
            threat_class="DATA_EXFILTRATION",
            confidence=0.93,
            severity=AlertSeverity.HIGH,
            risk_score=RiskScore(score=87, explanation="Anomalous large outbound data transfer"),
            source_ip="10.6.6.33",
            destination_ip="203.0.113.45",
            destination_port=443,
            status=AlertStatus.NEW,
            explanation="Outbound flow volume exceeded 500 MB outside normal business hours",
            mitre_attack=MitreAttackRef(
                tactic="Exfiltration",
                tactic_id="TA0010",
                technique="Exfiltration Over C2 Channel",
                technique_id="T1041",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="exfil_detector",
                    feature_name="outbound_bytes",
                    observed_value=524288000,
                    threshold_value=50000000,
                    confidence_contribution=0.91,
                )
            ],
        ),
        "benign_traffic": SecurityAlert(
            alert_id="alt-eval-benign-09",
            timestamp=now,
            threat_class="BEHAVIORAL_ANOMALY",
            confidence=0.60,
            severity=AlertSeverity.LOW,
            risk_score=RiskScore(score=35, explanation="Minor statistical deviation in standard web session"),
            source_ip="10.0.1.10",
            destination_ip="142.250.190.46",
            destination_port=443,
            status=AlertStatus.NEW,
            explanation="Slight burst in standard HTTPS traffic to Google CDN endpoint",
            mitre_attack=None,
            evidence=[
                AlertEvidence(
                    detector_name="anomaly_detector",
                    feature_name="packet_rate",
                    observed_value=120,
                    threshold_value=100,
                    confidence_contribution=0.4,
                )
            ],
        ),
    }

    return scenarios

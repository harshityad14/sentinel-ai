"""Seeds sentinel.db with realistic development records using SentinelAI domain models."""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "packages" / "models"))
sys.path.insert(0, str(repo_root / "packages" / "ingestion"))
sys.path.insert(0, str(repo_root / "packages" / "flow_engine"))
sys.path.insert(0, str(repo_root / "packages" / "streaming"))
sys.path.insert(0, str(repo_root / "packages" / "detection"))
sys.path.insert(0, str(repo_root / "packages" / "correlation"))
sys.path.insert(0, str(repo_root / "apps" / "api"))

from app.db.session import SessionLocal
from app.repositories.flow_repo import FlowRepository
from app.repositories.detection_repo import DetectionRepository
from app.repositories.alert_repo import AlertRepository
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.detection import (
    DetectionResult,
    DetectionEvidence,
    ThreatType,
    DetectorType,
    DetectionSeverity,
)
from sentinel_models.alerts import (
    SecurityAlert,
    AlertEvidence,
    AlertSignal,
    AlertSeverity,
    AlertStatus,
    ThreatCategory,
    RiskScore,
)


def seed_database():
    db = SessionLocal()
    flow_repo = FlowRepository(db)
    det_repo = DetectionRepository(db)
    alert_repo = AlertRepository(db)

    # Check if already seeded
    existing_alerts = alert_repo.list_alerts()[1]
    if existing_alerts > 0:
        print(f"Database already contains {existing_alerts} alerts. Skipping seed.")
        db.close()
        return

    now = datetime.now(timezone.utc)

    # Define alert templates with realistic threat data
    seed_configs = [
        {
            "id": "alt-sec-001",
            "title": "SYN Flood Denial of Service Attack",
            "threat_class": "SYN_FLOOD",
            "category": ThreatCategory.DDOS,
            "severity": AlertSeverity.CRITICAL,
            "status": AlertStatus.ACTIVE,
            "confidence": 0.98,
            "risk_score": 94,
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.5",
            "explanation": "High volume of TCP SYN packets (12,400 pkts/sec) without ACK handshakes, exhausting connection tables.",
            "detector_name": "syn_flood_detector",
        },
        {
            "id": "alt-sec-002",
            "title": "DNS Tunneling Data Exfiltration",
            "threat_class": "DNS_TUNNELING",
            "category": ThreatCategory.DATA_EXFILTRATION,
            "severity": AlertSeverity.CRITICAL,
            "status": AlertStatus.NEW,
            "confidence": 0.92,
            "risk_score": 88,
            "src_ip": "192.168.1.42",
            "dst_ip": "8.8.8.8",
            "explanation": "Anomalously large TXT record queries with high Shannon entropy payload indicating encoded data exfiltration.",
            "detector_name": "dns_entropy_detector",
        },
        {
            "id": "alt-sec-003",
            "title": "C2 Periodic Beaconing Observed",
            "threat_class": "C2_BEACONING",
            "category": ThreatCategory.C2_BEACONING,
            "severity": AlertSeverity.HIGH,
            "status": AlertStatus.ACTIVE,
            "confidence": 0.89,
            "risk_score": 81,
            "src_ip": "192.168.1.77",
            "dst_ip": "185.220.101.5",
            "explanation": "Strict 60.0s periodic heartbeat beacon observed matching known Cobalt Strike command & control profile.",
            "detector_name": "beaconing_detector",
        },
        {
            "id": "alt-sec-004",
            "title": "Horizontal Reconnaissance Port Scan",
            "threat_class": "PORT_SCAN",
            "category": ThreatCategory.PORT_SCAN,
            "severity": AlertSeverity.MEDIUM,
            "status": AlertStatus.RESOLVED,
            "confidence": 0.85,
            "risk_score": 58,
            "src_ip": "10.0.2.15",
            "dst_ip": "192.168.1.1",
            "explanation": "Sequential connection attempts to 1,024 destination ports within 2.5 seconds.",
            "detector_name": "port_scan_detector",
        },
        {
            "id": "alt-sec-005",
            "title": "Suspicious TLS Certificate Anomaly",
            "threat_class": "SUSPICIOUS_TLS",
            "category": ThreatCategory.SUSPICIOUS_ENCRYPTED_FLOW,
            "severity": AlertSeverity.LOW,
            "status": AlertStatus.NEW,
            "confidence": 0.76,
            "risk_score": 35,
            "src_ip": "192.168.1.18",
            "dst_ip": "104.244.42.1",
            "explanation": "Self-signed certificate with untrusted CA authority and mismatched SNI domain.",
            "detector_name": "tls_fingerprint_detector",
        },
    ]

    for idx, cfg in enumerate(seed_configs):
        flow_id = f"flw-{idx + 1:04d}"
        det_id = f"det-{idx + 1:04d}"
        delta = timedelta(minutes=(idx * 12 + 3))

        flow = FlowRecord(
            flow_id=flow_id,
            start_time=now - delta - timedelta(seconds=45),
            end_time=now - delta,
            duration_sec=45.0,
            source_ip=cfg["src_ip"],
            destination_ip=cfg["dst_ip"],
            source_port=49152 + idx * 100,
            destination_port=80 if idx % 2 == 0 else 443,
            protocol=ProtocolType.TCP,
            total_packets=1250 + idx * 300,
            total_bytes=840000 + idx * 120000,
            forward_packets=800 + idx * 200,
            backward_packets=450 + idx * 100,
            forward_bytes=520000 + idx * 80000,
            backward_bytes=320000 + idx * 40000,
            tcp_flags={"SYN": 120, "ACK": 45, "FIN": 1},
        )
        flow_repo.create_flow(flow)

        ev = DetectionEvidence(
            feature_name="anomaly_ratio",
            observed_value=0.95,
            threshold_value=0.80,
            description=cfg["explanation"],
        )
        det = DetectionResult(
            detection_id=det_id,
            flow_id=flow_id,
            threat_type=ThreatType[cfg["threat_class"]],
            detector_type=DetectorType.RULE,
            severity=DetectionSeverity[cfg["severity"].value],
            confidence=cfg["confidence"],
            evidence=[ev],
            detection_timestamp=now - delta,
            explanation=cfg["explanation"],
        )
        det_repo.create_detection(det)

        sig = AlertSignal(
            signal_id=f"sig-{idx + 1:04d}",
            flow_id=flow_id,
            threat_type=cfg["threat_class"],
            detector_type="RULE",
            detector_name=cfg["detector_name"],
            severity=cfg["severity"].value,
            confidence=cfg["confidence"],
            timestamp=now - delta,
        )
        alert_ev = AlertEvidence(
            detector_name=cfg["detector_name"],
            detection_type="rule",
            feature_name="observed_anomaly",
            observed_value=0.95,
            threshold_value=0.80,
            confidence_contribution=cfg["confidence"],
            description=cfg["explanation"],
        )
        alert = SecurityAlert(
            alert_id=cfg["id"],
            timestamp=now - delta,
            first_seen=now - delta - timedelta(minutes=5),
            last_seen=now - delta,
            source_ip=cfg["src_ip"],
            destination_ip=cfg["dst_ip"],
            threat_class=cfg["threat_class"],
            category=cfg["category"],
            severity=cfg["severity"],
            status=cfg["status"],
            confidence=cfg["confidence"],
            risk_score=RiskScore(
                score=cfg["risk_score"],
                confidence_factor=cfg["confidence"],
                severity_factor=0.9,
                breakdown={"confidence": 0.45, "severity": 0.45},
                explanation=cfg["explanation"],
            ),
            explanation=cfg["explanation"],
            evidence=[alert_ev],
            contributing_signals=[sig],
            flow_ids=[flow_id],
        )
        alert_repo.create_alert(alert)

    db.commit()
    db.close()
    print("Successfully seeded SentinelAI SQLite database with 5 realistic alerts and flows.")


if __name__ == "__main__":
    seed_database()

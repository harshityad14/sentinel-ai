"""Performance Benchmark for Phase 5 Backend & Persistence Layer."""

import time
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.repositories.flow_repo import FlowRepository
from app.repositories.detection_repo import DetectionRepository
from app.repositories.alert_repo import AlertRepository
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.detection import DetectionResult, DetectionEvidence, ThreatType, DetectorType, DetectionSeverity
from sentinel_models.alerts import (
    SecurityAlert,
    AlertEvidence,
    AlertSignal,
    AlertSeverity,
    AlertStatus,
    ThreatCategory,
    RiskScore,
)


def run_backend_benchmark():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    db = SessionLocal()
    flow_repo = FlowRepository(db)
    det_repo = DetectionRepository(db)
    alert_repo = AlertRepository(db)

    print("\n" + "=" * 60)
    print("SENTINEL-AI PHASE 5 BACKEND & PERSISTENCE BENCHMARK")
    print("=" * 60)

    # 1. Insertion Throughput Benchmark (500 records)
    NUM_RECORDS = 500
    now = datetime.now(timezone.utc)

    t0 = time.perf_counter()
    for i in range(NUM_RECORDS):
        flow = FlowRecord(
            flow_id=f"bench_flow_{i:04d}",
            start_time=now - timedelta(seconds=i),
            end_time=now,
            duration_sec=float(i % 30),
            source_ip=f"10.0.{i % 10}.{i % 250}",
            destination_ip="192.168.1.1",
            source_port=10000 + (i % 50000),
            destination_port=80 if i % 2 == 0 else 443,
            protocol=ProtocolType.TCP,
            total_packets=10,
            total_bytes=1000,
            forward_packets=5,
            backward_packets=5,
            forward_bytes=500,
            backward_bytes=500,
        )
        flow_repo.create_flow(flow)

        ev = DetectionEvidence(
            feature_name="syn_ratio",
            observed_value=0.95,
            threshold_value=0.8,
            description="SYN Flood indicator",
        )
        det = DetectionResult(
            detection_id=f"bench_det_{i:04d}",
            flow_id=f"bench_flow_{i:04d}",
            threat_type=ThreatType.PORT_SCAN if i % 2 == 0 else ThreatType.SYN_FLOOD,
            detector_type=DetectorType.RULE,
            severity=DetectionSeverity.HIGH if i % 3 == 0 else DetectionSeverity.MEDIUM,
            confidence=0.85 + (i % 15) * 0.01,
            evidence=[ev],
            detection_timestamp=now - timedelta(seconds=i),
            explanation="Benchmark detected anomaly",
        )
        det_repo.create_detection(det)

        sig = AlertSignal(
            signal_id=f"sig_bench_{i:04d}",
            flow_id=f"bench_flow_{i:04d}",
            threat_type="Port Scan Detected",
            detector_type="RULE",
            detector_name="PortScanDetector",
            severity="HIGH",
            confidence=0.9,
            timestamp=now,
        )
        alert_ev = AlertEvidence(
            detector_name="PortScanDetector",
            detection_type="rule",
            feature_name="syn_ratio",
            observed_value=0.95,
            threshold_value=0.8,
            confidence_contribution=0.9,
            description="Synthetic benchmark evidence",
        )
        alert = SecurityAlert(
            alert_id=f"bench_alert_{i:04d}",
            timestamp=now - timedelta(seconds=i),
            first_seen=now - timedelta(seconds=i + 10),
            last_seen=now - timedelta(seconds=i),
            source_ip=f"10.0.{i % 10}.{i % 250}",
            destination_ip="192.168.1.1",
            threat_class="PORT_SCAN" if i % 2 == 0 else "SYN_FLOOD",
            category=ThreatCategory.PORT_SCAN if i % 2 == 0 else ThreatCategory.DDOS,
            severity=AlertSeverity.HIGH if i % 3 == 0 else AlertSeverity.MEDIUM,
            status=AlertStatus.NEW,
            confidence=0.9,
            risk_score=RiskScore(
                score=int(50 + (i % 50)),
                confidence_factor=0.9,
                severity_factor=0.8,
                breakdown={"confidence": 0.4, "severity": 0.4},
                explanation="Benchmark risk",
            ),
            explanation="Benchmark synthetic security alert",
            evidence=[alert_ev],
            contributing_signals=[sig],
            flow_ids=[f"bench_flow_{i:04d}"],
        )
        alert_repo.create_alert(alert)

    db.commit()
    t_insert = time.perf_counter() - t0
    total_entities_inserted = NUM_RECORDS * 3
    insert_throughput = total_entities_inserted / t_insert
    print(f"[*] Inserted {total_entities_inserted} database records in {t_insert:.3f}s ({insert_throughput:.1f} inserts/sec)")

    # 2. Paginated Flow Query Latency (100 queries)
    flow_latencies = []
    for _ in range(100):
        t_start = time.perf_counter()
        resp = client.get("/api/v1/flows?limit=50&offset=0")
        flow_latencies.append((time.perf_counter() - t_start) * 1000)
    avg_flow_latency_ms = sum(flow_latencies) / len(flow_latencies)
    print(f"[*] Paginated Flow Query Latency: {avg_flow_latency_ms:.2f} ms (avg of 100 requests)")

    # 3. Alert Query Latency (100 queries with filter and sort)
    alert_latencies = []
    for _ in range(100):
        t_start = time.perf_counter()
        resp = client.get("/api/v1/alerts?severity=HIGH&limit=25&offset=0&sort_by=risk_score&sort_desc=true")
        alert_latencies.append((time.perf_counter() - t_start) * 1000)
    avg_alert_latency_ms = sum(alert_latencies) / len(alert_latencies)
    print(f"[*] Alert Query Latency (filtered & sorted): {avg_alert_latency_ms:.2f} ms (avg of 100 requests)")

    # 4. Detection Query Throughput (200 rapid queries)
    t_det_start = time.perf_counter()
    for _ in range(200):
        client.get("/api/v1/detections?threat_type=PORT_SCAN&limit=20")
    t_det_elapsed = time.perf_counter() - t_det_start
    detection_query_throughput = 200.0 / t_det_elapsed
    print(f"[*] Detection Query Throughput: {detection_query_throughput:.1f} queries/sec")

    print("=" * 60)
    print(f"BENCHMARK SUMMARY:")
    print(f"  alert_query_latency_ms: {avg_alert_latency_ms:.2f}")
    print(f"  flow_query_latency_ms: {avg_flow_latency_ms:.2f}")
    print(f"  detection_query_throughput_per_sec: {detection_query_throughput:.1f}")
    print(f"  insert_throughput_per_sec: {insert_throughput:.1f}")
    print("=" * 60 + "\n")

    db.close()
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


if __name__ == "__main__":
    run_backend_benchmark()

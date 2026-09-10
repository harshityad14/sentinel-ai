"""Comprehensive Unit & Integration Tests for Phase 5 FastAPI Backend & Persistence."""

import unittest
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
from app.services.alert_service import AlertService
from app.services.flow_service import FlowService
from app.services.detection_service import DetectionService

from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.detection import DetectionResult, DetectionEvidence, ThreatType, DetectionSeverity
from sentinel_models.alerts import (
    SecurityAlert,
    AlertEntity,
    AlertEntityType,
    AlertSignal,
    AlertEvidence,
    AlertSeverity,
    AlertStatus,
    ThreatCategory,
    RiskScore,
)


class BaseAPITestCase(unittest.TestCase):
    """Base test case providing an isolated in-memory SQLite database per test."""

    @classmethod
    def setUpClass(cls):
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=cls.test_engine
        )

    def setUp(self):
        Base.metadata.create_all(bind=self.test_engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.test_engine)
        app.dependency_overrides.clear()


class TestHealthAndReadiness(BaseAPITestCase):
    """Test health, readiness, and passive processing status endpoints."""

    def test_root_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("SentinelAI", data["service"])
        self.assertIn("Phase 5", data["phase"])

    def test_api_v1_health(self):
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)

    def test_api_v1_readiness(self):
        res = self.client.get("/api/v1/readiness")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ready")
        self.assertTrue(data["database"])

    def test_processing_status(self):
        res = self.client.get("/api/v1/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["pipeline_status"], "PASSIVE_INGESTION_ACTIVE")
        self.assertTrue(data["passive_mode_active"])


class TestDatabaseCRUDAndTransactions(BaseAPITestCase):
    """Test repository/service separation and database transactions."""

    def test_flow_crud_and_commit(self):
        repo = FlowRepository(self.db)
        flow = FlowRecord(
            flow_id="test_flow_crud_01",
            start_time=datetime.fromtimestamp(1700000000.0, tz=timezone.utc),
            end_time=datetime.fromtimestamp(1700000010.0, tz=timezone.utc),
            duration_sec=10.0,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=44556,
            destination_port=80,
            protocol=ProtocolType.TCP,
            total_packets=20,
            total_bytes=2000,
            forward_packets=12,
            backward_packets=8,
            forward_bytes=1200,
            backward_bytes=800,
        )
        db_flow = repo.create_flow(flow)
        self.db.commit()

        retrieved = repo.get_by_flow_id("test_flow_crud_01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.src_ip, "192.168.1.50")
        self.assertEqual(retrieved.dst_port, 80)
        self.assertTrue(retrieved.is_bidirectional)

    def test_transaction_rollback_on_error(self):
        repo = FlowRepository(self.db)
        flow = FlowRecord(
            flow_id="rollback_flow_01",
            start_time=datetime.fromtimestamp(1700000000.0, tz=timezone.utc),
            end_time=datetime.fromtimestamp(1700000010.0, tz=timezone.utc),
            duration_sec=10.0,
            source_ip="192.168.1.99",
            destination_ip="10.0.0.2",
            source_port=50000,
            destination_port=443,
            protocol=ProtocolType.TCP,
            total_packets=5,
            total_bytes=500,
            forward_packets=3,
            backward_packets=2,
            forward_bytes=300,
            backward_bytes=200,
        )
        repo.create_flow(flow)
        self.db.rollback()

        retrieved = repo.get_by_flow_id("rollback_flow_01")
        self.assertIsNone(retrieved)


class TestAlertLifecycleAndQueries(BaseAPITestCase):
    """Test alert queries, filtering, sorting, pagination, and internal lifecycle transitions."""

    def _create_sample_alert(
        self,
        alert_id: str,
        threat_category: ThreatCategory = ThreatCategory.PORT_SCAN,
        severity: AlertSeverity = AlertSeverity.HIGH,
        risk_score: float = 78.5,
        confidence: float = 0.95,
        status: AlertStatus = AlertStatus.NEW,
    ) -> SecurityAlert:
        sig = AlertSignal(
            signal_id=f"sig_{alert_id}",
            flow_id=f"flow_{alert_id}",
            threat_type="Port Scan Detected",
            detector_type="RULE",
            detector_name="PortScanDetector",
            severity="HIGH",
            confidence=0.92,
            timestamp=datetime.now(timezone.utc),
        )
        ev = AlertEvidence(
            detector_name="PortScanDetector",
            detection_type="rule",
            feature_name="syn_ratio",
            observed_value=0.98,
            threshold_value=0.8,
            confidence_contribution=0.95,
            description="High SYN packet ratio with minimal completions",
        )
        ent = AlertEntity(
            entity_type=AlertEntityType.IP,
            identifier="192.168.1.100",
            role="SOURCE",
            confidence=1.0,
        )
        risk = RiskScore(
            score=int(risk_score),
            confidence_factor=confidence,
            severity_factor=0.8,
            breakdown={"confidence": 0.3, "severity": 0.5},
            explanation="Elevated multi-port scanning pattern",
        )
        now = datetime.now(timezone.utc)
        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=now,
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            threat_class=threat_category.value,
            category=threat_category,
            severity=severity,
            status=status,
            confidence=confidence,
            risk_score=risk,
            explanation="Automated port scanning pattern against internal subnet",
            evidence=[ev],
            contributing_signals=[sig],
            flow_ids=[f"flow_{alert_id}"],
        )
        service = AlertService(self.db)
        service.persist_alert(alert)
        self.db.commit()
        return alert

    def test_alert_retrieval_and_details(self):
        self._create_sample_alert("alert-001")
        res = self.client.get("/api/v1/alerts/alert-001")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["alert_id"], "alert-001")
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["status"], "NEW")
        self.assertEqual(len(data["signals"]), 1)
        self.assertEqual(len(data["evidence_items"]), 1)
        self.assertEqual(len(data["entities"]), 2)
        self.assertEqual(len(data["lifecycle_history"]), 1)

    def test_alert_not_found(self):
        res = self.client.get("/api/v1/alerts/nonexistent-alert")
        self.assertEqual(res.status_code, 404)
        self.assertIn("not found", res.json()["message"].lower())

    def test_alert_acknowledgement_lifecycle(self):
        self._create_sample_alert("alert-ack-01")
        res = self.client.post(
            "/api/v1/alerts/alert-ack-01/acknowledge",
            json={"changed_by": "analyst_alice", "notes": "Investigating reconnaissance sweep"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ACKNOWLEDGED")
        self.assertEqual(len(data["lifecycle_history"]), 2)
        self.assertEqual(data["lifecycle_history"][0]["new_status"], "ACKNOWLEDGED")
        self.assertEqual(data["lifecycle_history"][0]["changed_by"], "analyst_alice")

    def test_alert_resolution_lifecycle(self):
        self._create_sample_alert("alert-res-01")
        res = self.client.post(
            "/api/v1/alerts/alert-res-01/resolve",
            json={"changed_by": "analyst_bob", "notes": "Benign vulnerability scan verified"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(len(data["lifecycle_history"]), 2)
        self.assertEqual(data["lifecycle_history"][0]["new_status"], "RESOLVED")

    def test_alert_pagination(self):
        for i in range(15):
            self._create_sample_alert(f"alert-page-{i:02d}", risk_score=float(i * 5))

        # First page (limit 5)
        res = self.client.get("/api/v1/alerts?limit=5&offset=0")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["items"]), 5)
        self.assertEqual(data["total"], 15)
        self.assertTrue(data["has_more"])

        # Third page (limit 5, offset 10)
        res = self.client.get("/api/v1/alerts?limit=5&offset=10")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["items"]), 5)
        self.assertFalse(data["has_more"])

    def test_alert_filtering_and_sorting(self):
        self._create_sample_alert("alert-low", severity=AlertSeverity.LOW, risk_score=20.0, threat_category=ThreatCategory.PORT_SCAN)
        self._create_sample_alert("alert-crit", severity=AlertSeverity.CRITICAL, risk_score=95.0, threat_category=ThreatCategory.DATA_EXFILTRATION)

        # Filter by severity
        res = self.client.get("/api/v1/alerts?severity=CRITICAL")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["alert_id"], "alert-crit")

        # Filter by risk range
        res = self.client.get("/api/v1/alerts?min_risk=80.0")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["alert_id"], "alert-crit")

    def test_alert_statistics(self):
        self._create_sample_alert("alert-s1", severity=AlertSeverity.HIGH)
        self._create_sample_alert("alert-s2", severity=AlertSeverity.CRITICAL)

        res = self.client.get("/api/v1/alerts/statistics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_alerts"], 2)
        self.assertIn("HIGH", data["by_severity"])
        self.assertIn("CRITICAL", data["by_severity"])


class TestFlowAndDetectionAPIs(BaseAPITestCase):
    """Test network flow and threat detection endpoints."""

    def test_flow_query_and_details(self):
        service = FlowService(self.db)
        flow = FlowRecord(
            flow_id="fl_test_99",
            start_time=datetime.fromtimestamp(1700000000.0, tz=timezone.utc),
            end_time=datetime.fromtimestamp(1700000005.0, tz=timezone.utc),
            duration_sec=5.0,
            source_ip="10.1.1.20",
            destination_ip="10.1.1.80",
            source_port=12345,
            destination_port=80,
            protocol=ProtocolType.TCP,
            total_packets=10,
            total_bytes=1000,
            forward_packets=5,
            backward_packets=5,
            forward_bytes=500,
            backward_bytes=500,
        )
        service.persist_flow(flow)
        self.db.commit()

        # Query list with IP filter
        res = self.client.get("/api/v1/flows?src_ip=10.1.1.20")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["flow_id"], "fl_test_99")

        # Query single flow
        res = self.client.get("/api/v1/flows/fl_test_99")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["src_ip"], "10.1.1.20")

        # 404 for missing flow
        res = self.client.get("/api/v1/flows/nonexistent_flow")
        self.assertEqual(res.status_code, 404)

    def test_detection_query_and_details(self):
        from sentinel_models.detection import DetectorType
        service = DetectionService(self.db)
        ev = DetectionEvidence(
            feature_name="syn_ratio",
            observed_value=0.99,
            threshold_value=0.8,
            description="Abnormally elevated SYN packet frequency",
        )
        det = DetectionResult(
            detection_id="det_test_01",
            flow_id="fl_test_99",
            threat_type=ThreatType.SYN_FLOOD,
            detector_type=DetectorType.RULE,
            severity=DetectionSeverity.HIGH,
            confidence=0.96,
            evidence=[ev],
            detection_timestamp=datetime.now(timezone.utc),
            explanation="TCP SYN flood volumetric anomaly detected",
        )
        service.persist_detection(det)
        self.db.commit()

        # List detections
        res = self.client.get("/api/v1/detections?threat_type=SYN_FLOOD")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["detection_id"], "det_test_01")
        self.assertEqual(len(data["items"][0]["evidence_items"]), 1)

        # Single detection
        res = self.client.get("/api/v1/detections/det_test_01")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["detector_name"], "RULE")

        # 404 for missing detection
        res = self.client.get("/api/v1/detections/det_unknown")
        self.assertEqual(res.status_code, 404)


class TestValidationAndErrorResponses(BaseAPITestCase):
    """Test validation errors, invalid parameters, and safe error responses."""

    def test_invalid_pagination_limit(self):
        res = self.client.get("/api/v1/alerts?limit=0")
        self.assertEqual(res.status_code, 422)
        data = res.json()
        self.assertEqual(data["error"], "VALIDATION_ERROR")

    def test_invalid_confidence_range(self):
        res = self.client.get("/api/v1/alerts?min_confidence=1.5")
        self.assertEqual(res.status_code, 422)
        data = res.json()
        self.assertEqual(data["error"], "VALIDATION_ERROR")


if __name__ == "__main__":
    unittest.main()

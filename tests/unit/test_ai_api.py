"""Unit and integration tests for FastAPI GenAI Security Analyst endpoints."""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1.endpoints.ai_analyst import get_ai_service
from app.core.rate_limiter import ai_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.repositories.alert_repo import AlertRepository
from sentinel_ai_agent.config import AIAnalystConfig
from sentinel_ai_agent.providers.mock import MockLLMProvider
from sentinel_ai_agent.service import GenAIAnalystService
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    MitreAttackRef,
    RiskScore,
    SecurityAlert,
)


class TestAIEndpoints(unittest.TestCase):
    """Test suite verifying /analyze, /analysis, /ask, and /ai/health endpoints."""

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
        ai_rate_limiter.reset()

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

        # Configure deterministic mock service
        self.mock_provider = MockLLMProvider()
        self.test_service = GenAIAnalystService(
            config=AIAnalystConfig(rate_limit_rpm=5, timeout_seconds=2.0),
            provider=self.mock_provider,
        )

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_ai_service] = lambda: self.test_service
        self.client = TestClient(app)

        # Seed sample alert
        self.alert_repo = AlertRepository(self.db)
        self.test_alert = SecurityAlert(
            alert_id="alt-api-test-01",
            timestamp=datetime.now(timezone.utc),
            threat_class="SYN_FLOOD",
            confidence=0.98,
            severity=AlertSeverity.CRITICAL,
            risk_score=RiskScore(score=92, explanation="Severe SYN flood"),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            source_port=54321,
            destination_port=80,
            status=AlertStatus.NEW,
            explanation="5400 SYN packets without handshakes",
            mitre_attack=MitreAttackRef(
                tactic="Impact",
                tactic_id="TA0040",
                technique="Network Denial of Service",
                technique_id="T1498",
            ),
            evidence=[
                AlertEvidence(
                    detector_name="syn_detector",
                    feature_name="syn_ratio",
                    observed_value=0.98,
                    threshold_value=0.85,
                )
            ],
            contributing_signals=[
                AlertSignal(
                    signal_id="sig-01",
                    flow_id="fl-01",
                    threat_type="SYN_FLOOD",
                    detector_type="RULE",
                    detector_name="syn_detector",
                    confidence=0.98,
                    severity="CRITICAL",
                )
            ],
        )
        self.alert_repo.create_alert(self.test_alert)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.test_engine)
        app.dependency_overrides.clear()
        ai_rate_limiter.reset()

    def test_ai_health_endpoint(self):
        resp = self.client.get("/api/v1/ai/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("provider", data)
        self.assertIn("cache", data)
        self.assertIn("metrics", data)

    def test_analyze_alert_nonexistent(self):
        resp = self.client.post("/api/v1/alerts/alt-nonexistent/analyze")
        self.assertEqual(resp.status_code, 404)

    def test_analyze_alert_success(self):
        resp = self.client.post("/api/v1/alerts/alt-api-test-01/analyze")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["alert_id"], "alt-api-test-01")
        self.assertIn("SYN_FLOOD", data["executive_summary"])
        self.assertFalse(data["is_fallback"])
        self.assertEqual(data["validation_log"]["validation_status"], "PASSED")
        self.assertTrue(len(data["recommended_investigation_steps"]) > 0)

    def test_get_cached_analysis(self):
        # 1. Before analyze -> 404
        resp_before = self.client.get("/api/v1/alerts/alt-api-test-01/analysis")
        self.assertEqual(resp_before.status_code, 404)

        # 2. Run analyze
        resp_run = self.client.post("/api/v1/alerts/alt-api-test-01/analyze")
        self.assertEqual(resp_run.status_code, 200)

        # 3. Get cached -> 200 with cache_hit=True
        resp_cached = self.client.get("/api/v1/alerts/alt-api-test-01/analysis")
        self.assertEqual(resp_cached.status_code, 200)
        cached_data = resp_cached.json()
        self.assertTrue(cached_data["cache_hit"])

    def test_ask_question_validation_and_success(self):
        # Too short (Pydantic returns 422, endpoint returns 400 or 422)
        resp_short = self.client.post(
            "/api/v1/alerts/alt-api-test-01/ask",
            json={"question": "hi"},
        )
        self.assertIn(resp_short.status_code, (400, 422))

        # Too long
        resp_long = self.client.post(
            "/api/v1/alerts/alt-api-test-01/ask",
            json={"question": "x" * 501},
        )
        self.assertIn(resp_long.status_code, (400, 422))

        # Valid question
        resp_valid = self.client.post(
            "/api/v1/alerts/alt-api-test-01/ask",
            json={"question": "What was the observed SYN ratio?"},
        )
        self.assertEqual(resp_valid.status_code, 200)
        data = resp_valid.json()
        self.assertEqual(data["alert_id"], "alt-api-test-01")
        self.assertTrue(data["grounded_in_telemetry"])
        self.assertIsNotNone(data["answer"])

    def test_fallback_returns_http_200(self):
        # Configure service with failing provider
        failing_provider = MockLLMProvider(should_fail=True)
        failing_service = GenAIAnalystService(
            config=AIAnalystConfig(),
            provider=failing_provider,
        )
        app.dependency_overrides[get_ai_service] = lambda: failing_service

        resp = self.client.post("/api/v1/alerts/alt-api-test-01/analyze")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["is_fallback"])
        self.assertIn("Provider mock error", data["fallback_reason"])
        self.assertIn("192.168.1.100", data["executive_summary"])

    def test_rate_limiting_enforcement(self):
        # Explicitly configure limiter to 5 rpm for this test
        ai_rate_limiter.requests_per_minute = 5
        for i in range(5):
            r = self.client.post("/api/v1/alerts/alt-api-test-01/ask", json={"question": f"Question {i}?"})
            self.assertEqual(r.status_code, 200)

        # 6th request from same IP should be blocked with 429
        r_blocked = self.client.post("/api/v1/alerts/alt-api-test-01/ask", json={"question": "Question 6?"})
        self.assertEqual(r_blocked.status_code, 429)


if __name__ == "__main__":
    unittest.main()

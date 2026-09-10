"""Unit and integration tests for security headers, CSP, HSTS, and observability endpoints."""

import unittest
from fastapi.testclient import TestClient

from app.main import app


class TestSecurityHeadersAndObservability(unittest.TestCase):
    """Test suite verifying security headers middleware, CSP, HSTS, and metrics."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_baseline_security_headers_present(self):
        """Verify baseline defense-in-depth security headers on all responses."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)

        headers = res.headers
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("x-xss-protection"), "1; mode=block")
        self.assertEqual(headers.get("referrer-policy"), "strict-origin-when-cross-origin")
        self.assertIn("accelerometer=()", headers.get("permissions-policy", ""))

    def test_csp_header_contains_required_directives(self):
        """Verify Content-Security-Policy supports Google Fonts and WebSockets."""
        res = self.client.get("/health")
        csp = res.headers.get("content-security-policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("https://fonts.googleapis.com", csp)
        self.assertIn("https://fonts.gstatic.com", csp)
        self.assertIn("connect-src 'self' ws: wss:", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_hsts_omitted_over_plain_http(self):
        """Verify HSTS is NOT emitted over plain HTTP connections."""
        res = self.client.get("http://testserver/health")
        self.assertNotIn("strict-transport-security", res.headers)

    def test_hsts_emitted_when_forwarded_proto_is_https(self):
        """Verify HSTS is emitted when TLS is terminated upstream by reverse proxy."""
        res = self.client.get("http://testserver/health", headers={"x-forwarded-proto": "https"})
        self.assertIn("strict-transport-security", res.headers)
        self.assertIn("max-age=31536000", res.headers.get("strict-transport-security"))

    def test_root_health_enrichment(self):
        """Verify root /health endpoint includes passive operational assertions."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn(data["status"], ["healthy", "degraded"])
        self.assertTrue(data.get("passive_mode"))
        self.assertIn("database", data)
        self.assertIn("version", data)
        self.assertIn("environment", data)

    def test_prometheus_metrics_endpoint(self):
        """Verify /metrics provides standard Prometheus text format."""
        res = self.client.get("/metrics")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/plain", res.headers.get("content-type", ""))
        body = res.text
        self.assertIn("sentinel_api_info", body)
        self.assertIn("sentinel_api_uptime_seconds", body)
        self.assertIn("sentinel_database_status", body)
        self.assertIn("sentinel_passive_mode_enforced 1", body)

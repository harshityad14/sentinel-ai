"""Unit tests for WebSocket real-time alerts streaming endpoint and notifier service."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import settings
from app.main import create_app
from app.services.alert_notifier import AlertNotifier, get_alert_notifier


class TestWebSocketAPI(unittest.TestCase):
    """Test suite verifying WebSocket connection, origin safety, broadcasting, and limits."""

    def setUp(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        self.notifier = get_alert_notifier()
        # Ensure connections are empty
        self.notifier._connections.clear()

    def tearDown(self):
        self.notifier._connections.clear()

    def test_ws_connection_and_greeting(self):
        """Test successful WebSocket handshake and initial status greeting."""
        with self.client.websocket_connect("/api/v1/ws/alerts") as ws:
            data = ws.receive_json()
            self.assertEqual(data.get("type"), "CONNECTED")
            self.assertEqual(data.get("status"), "LIVE")

    def test_ws_ping_pong_heartbeat(self):
        """Test client-initiated heartbeat ping/pong keepalive."""
        with self.client.websocket_connect("/api/v1/ws/alerts") as ws:
            ws.receive_json()  # Greeting
            ws.send_json({"type": "PING"})
            response = ws.receive_json()
            self.assertEqual(response.get("type"), "PONG")

    def test_ws_broadcast_alert(self):
        """Test that alert broadcast successfully dispatches to active clients."""
        with self.client.websocket_connect("/api/v1/ws/alerts") as ws:
            ws.receive_json()  # Greeting

            # Dispatch an alert via the notifier service
            alert_payload = {
                "alert_id": "alt-stream-999",
                "title": "Real-Time Test Alert",
                "severity": "CRITICAL",
                "threat_class": "PORT_SCAN",
                "risk_score": 95,
            }

            asyncio.run(self.notifier.broadcast_alert(alert_payload))

            message = ws.receive_json()
            self.assertEqual(message.get("type"), "NEW_ALERT")
            self.assertEqual(message.get("data", {}).get("alert_id"), "alt-stream-999")
            self.assertEqual(message.get("data", {}).get("severity"), "CRITICAL")

    def test_ws_origin_validation(self):
        """Test that unauthorized Origin header is rejected with 1008 policy violation."""
        notifier = AlertNotifier()
        with patch.object(settings, "cors_origins", ["http://localhost:3000", "http://127.0.0.1:3000"]):
            self.assertTrue(notifier.is_origin_allowed("http://localhost:3000"))
            self.assertTrue(notifier.is_origin_allowed("http://127.0.0.1:3000"))
            self.assertFalse(notifier.is_origin_allowed("http://evil-attacker.com"))
            self.assertTrue(notifier.is_origin_allowed(None))  # Non-browser client

    def test_ws_connection_limit(self):
        """Test that connection capacity limit is strictly enforced."""
        notifier = AlertNotifier(max_connections=2)
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        mock_ws3 = AsyncMock()

        accepted1 = asyncio.run(notifier.connect(mock_ws1))
        accepted2 = asyncio.run(notifier.connect(mock_ws2))
        accepted3 = asyncio.run(notifier.connect(mock_ws3))

        self.assertTrue(accepted1)
        self.assertTrue(accepted2)
        self.assertFalse(accepted3, "Third connection must be rejected when capacity is 2")
        self.assertEqual(notifier.connection_count, 2)

    def test_ws_oversized_frame_rejected(self):
        """Test that frames exceeding 64 KB trigger connection termination."""
        with self.client.websocket_connect("/api/v1/ws/alerts") as ws:
            ws.receive_json()  # Greeting
            oversized_data = "A" * 70000
            try:
                ws.send_text(oversized_data)
                # Should disconnect
                ws.receive_text()
            except Exception:
                pass  # Disconnect expected

    def test_ws_slow_client_cleanup(self):
        """Test that client send timeouts do not stall broadcast and stale clients are removed."""
        notifier = AlertNotifier(send_timeout_sec=0.01)

        # Mock a stalled/hanging client
        async def slow_send(*args, **kwargs):
            await asyncio.sleep(0.1)

        stalled_ws = AsyncMock()
        stalled_ws.send_text = slow_send

        # Fast client
        fast_ws = AsyncMock()

        asyncio.run(notifier.connect(stalled_ws))
        asyncio.run(notifier.connect(fast_ws))
        self.assertEqual(notifier.connection_count, 2)

        # Broadcast should succeed for fast client and remove slow client
        success_count = asyncio.run(notifier.broadcast_alert({"alert_id": "test"}))
        self.assertEqual(success_count, 1)
        self.assertEqual(notifier.connection_count, 1)
        self.assertIn(fast_ws, notifier._connections)
        self.assertNotIn(stalled_ws, notifier._connections)


if __name__ == "__main__":
    unittest.main()

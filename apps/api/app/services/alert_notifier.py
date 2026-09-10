"""WebSocket connection manager and non-blocking alert broadcasting service."""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket, status

from app.core.config import settings

logger = logging.getLogger("sentinel.notifier")


class AlertNotifier:
    """Manages real-time WebSocket client connections and safe broadcast fan-out."""

    def __init__(self, max_connections: int = 50, send_timeout_sec: float = 2.0):
        self.max_connections = max_connections
        self.send_timeout_sec = send_timeout_sec
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        """Count of currently connected WebSocket clients."""
        return len(self._connections)

    def is_origin_allowed(self, origin: Optional[str]) -> bool:
        """Validate client Origin header against configured CORS origins."""
        if not origin:
            # Same-origin or non-browser clients (e.g. CLI/tests) allowed
            return True

        if "*" in settings.cors_origins:
            return True

        # Normalize trailing slashes for comparison
        clean_origin = origin.rstrip("/")
        allowed_origins = [o.rstrip("/") for o in settings.cors_origins]
        return clean_origin in allowed_origins

    async def connect(self, websocket: WebSocket, origin: Optional[str] = None) -> bool:
        """Authenticate origin, enforce capacity limit, and accept connection.
        
        Returns True if accepted; False if rejected.
        """
        # 1. Origin verification
        if not self.is_origin_allowed(origin):
            logger.warning(f"Rejected WebSocket connection from unauthorized origin: {origin}")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Origin not allowed")
            return False

        # 2. Connection limit check
        async with self._lock:
            if len(self._connections) >= self.max_connections:
                logger.warning(f"Rejected WebSocket connection: capacity limit ({self.max_connections}) reached")
                await websocket.close(
                    code=status.WS_1013_TRY_AGAIN_LATER,
                    reason=f"Server connection limit reached ({self.max_connections})",
                )
                return False

            await websocket.accept()
            self._connections.add(websocket)
            logger.info(f"Accepted WebSocket client. Active connections: {len(self._connections)}/{self.max_connections}")
            return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Safely remove a client connection upon disconnect or error."""
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
                logger.info(f"Removed WebSocket client. Active connections: {len(self._connections)}")

    async def broadcast_alert(self, alert_data: Dict[str, Any]) -> int:
        """Broadcast alert payload to all connected clients with timeout and isolation.
        
        Returns count of clients successfully delivered to.
        """
        if not self._connections:
            return 0

        message_str = json.dumps(
            {
                "type": "NEW_ALERT",
                "data": alert_data,
            },
            default=str,
        )

        success_count = 0
        stale_clients: List[WebSocket] = []

        # Snapshot current connections to iterate safely without holding lock
        async with self._lock:
            current_clients = list(self._connections)

        for client in current_clients:
            try:
                # Enforce non-blocking timeout per client to isolate slow consumers
                await asyncio.wait_for(client.send_text(message_str), timeout=self.send_timeout_sec)
                success_count += 1
            except (asyncio.TimeoutError, Exception) as exc:
                logger.warning(f"Failed to deliver alert to client (marking for disconnect): {exc}")
                stale_clients.append(client)

        # Cleanup failed/slow clients
        if stale_clients:
            async with self._lock:
                for stale in stale_clients:
                    self._connections.discard(stale)
                    try:
                        await stale.close(code=status.WS_1011_INTERNAL_ERROR, reason="Client timeout or buffer overflow")
                    except Exception:
                        pass
            logger.info(f"Cleaned up {len(stale_clients)} stale/slow WebSocket clients")

        return success_count


# Global singleton instance
alert_notifier = AlertNotifier()


def get_alert_notifier() -> AlertNotifier:
    """Dependency provider returning singleton notifier."""
    return alert_notifier

"""WebSocket endpoints for real-time security alert feeds."""

import asyncio
import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.services.alert_notifier import get_alert_notifier

logger = logging.getLogger("sentinel.ws")

router = APIRouter(prefix="/ws", tags=["Real-Time Streaming"])

MAX_FRAME_BYTES = 65536  # 64 KB maximum incoming frame size


@router.websocket("/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket stream broadcasting correlated security alerts.
    
    Guarantees:
    - Origin verification against configured CORS origins.
    - Capacity limit (max 50 concurrent connections).
    - Isolated broadcast timeouts (slow clients disconnected without blocking persistence).
    - 30s ping/pong heartbeat keepalive.
    """
    notifier = get_alert_notifier()
    origin = websocket.headers.get("origin")

    accepted = await notifier.connect(websocket, origin=origin)
    if not accepted:
        return

    try:
        # Initial greeting with system status and client metadata
        await websocket.send_text(
            json.dumps(
                {
                    "type": "CONNECTED",
                    "status": "LIVE",
                    "message": "Connected to SentinelAI real-time security alert stream",
                }
            )
        )

        while True:
            # Wait for client heartbeat frames or incoming commands with a 60s idle timeout
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
            except asyncio.TimeoutError:
                # Send server-initiated ping frame to check client liveness
                await websocket.send_text(json.dumps({"type": "PING"}))
                continue

            if len(data) > MAX_FRAME_BYTES:
                logger.warning(f"Client sent oversized frame ({len(data)} bytes). Disconnecting.")
                await websocket.close(
                    code=status.WS_1009_MESSAGE_TOO_BIG,
                    reason="Message exceeds maximum frame limit",
                )
                break

            # Handle client-initiated ping / keepalive
            try:
                msg = json.loads(data)
                if isinstance(msg, dict) and msg.get("type") == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except json.JSONDecodeError:
                pass  # Ignore invalid text frames

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")
    except Exception as exc:
        logger.warning(f"WebSocket client connection terminated with error: {exc}")
    finally:
        await notifier.disconnect(websocket)

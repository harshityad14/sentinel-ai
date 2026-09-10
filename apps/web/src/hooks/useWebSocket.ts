import { useEffect, useRef, useState, useCallback } from "react";
import { SecurityAlertRead } from "../types/alert";
import { WebSocketConnectionStatus, WebSocketMessage } from "../types/websocket";

interface UseWebSocketOptions {
  onAlert?: (alert: SecurityAlertRead) => void;
  enabled?: boolean;
}

export function useWebSocket({ onAlert, enabled = true }: UseWebSocketOptions = {}) {
  const [status, setStatus] = useState<WebSocketConnectionStatus>("DISCONNECTED");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<any>(null);
  const heartbeatTimerRef = useRef<any>(null);
  const onAlertRef = useRef(onAlert);
  onAlertRef.current = onAlert;

  const connect = useCallback(() => {
    if (!enabled) return;

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/v1/ws/alerts`;

    setStatus((prev) => (prev === "DISCONNECTED" ? "CONNECTING" : "RECONNECTING"));

    try {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setStatus("CONNECTED");
        reconnectAttemptRef.current = 0;

        // Setup 30s client-side heartbeat
        clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "PING" }));
          }
        }, 30000);
      };

      socket.onmessage = (event) => {
        try {
          const msg: WebSocketMessage = JSON.parse(event.data);
          if (msg.type === "NEW_ALERT" && msg.data) {
            onAlertRef.current?.(msg.data);
          }
        } catch {
          // Ignore unparseable frames
        }
      };

      socket.onclose = () => {
        clearInterval(heartbeatTimerRef.current);
        wsRef.current = null;

        if (reconnectAttemptRef.current >= 6) {
          setStatus("POLLING_FALLBACK");
        } else {
          setStatus("RECONNECTING");
        }

        // Exponential backoff with jitter
        reconnectAttemptRef.current += 1;
        const baseDelay = Math.min(30000, 1000 * Math.pow(1.5, reconnectAttemptRef.current));
        const jitter = Math.random() * 1000;
        const delay = baseDelay + jitter;

        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, delay);
      };

      socket.onerror = () => {
        // Handled in onclose
      };
    } catch {
      setStatus("POLLING_FALLBACK");
    }
  }, [enabled]);

  useEffect(() => {
    if (enabled) {
      connect();
    }
    return () => {
      clearTimeout(reconnectTimerRef.current);
      clearInterval(heartbeatTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect, enabled]);

  return {
    status,
    reconnect: () => {
      reconnectAttemptRef.current = 0;
      connect();
    },
  };
}

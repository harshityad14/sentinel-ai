import React from "react";
import { WebSocketConnectionStatus } from "../../types/websocket";

interface ConnectionIndicatorProps {
  status: WebSocketConnectionStatus;
  reconnectCount?: number;
  onReconnect?: () => void;
}

export const ConnectionIndicator: React.FC<ConnectionIndicatorProps> = ({
  status,
  onReconnect,
}) => {
  const getDetails = () => {
    switch (status) {
      case "CONNECTED":
        return {
          label: "LIVE STREAM",
          color: "#10b981",
          bgColor: "rgba(16, 185, 129, 0.15)",
          pulsing: true,
        };
      case "CONNECTING":
      case "RECONNECTING":
        return {
          label: "RECONNECTING",
          color: "#f59e0b",
          bgColor: "rgba(245, 158, 11, 0.15)",
          pulsing: true,
        };
      case "POLLING_FALLBACK":
        return {
          label: "POLLING (WS OFFLINE)",
          color: "#06b6d4",
          bgColor: "rgba(6, 182, 212, 0.15)",
          pulsing: false,
        };
      default:
        return {
          label: "DISCONNECTED",
          color: "#ef4444",
          bgColor: "rgba(239, 68, 68, 0.15)",
          pulsing: false,
        };
    }
  };

  const { label, color, bgColor, pulsing } = getDetails();

  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.5rem",
        padding: "0.25rem 0.65rem",
        borderRadius: "9999px",
        background: bgColor,
        border: `1px solid ${color}40`,
        fontSize: "0.75rem",
        fontWeight: 600,
        color,
      }}
      title={
        status === "POLLING_FALLBACK"
          ? "WebSocket unavailable. Operating in fallback REST polling mode."
          : `Connection status: ${status}`
      }
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          backgroundColor: color,
          animation: pulsing ? "pulseGlow 1.5s infinite ease-in-out" : "none",
        }}
      />
      <span>{label}</span>
      {status === "POLLING_FALLBACK" && onReconnect && (
        <button
          onClick={onReconnect}
          style={{
            background: "none",
            border: "none",
            color: "inherit",
            textDecoration: "underline",
            cursor: "pointer",
            fontSize: "inherit",
            fontWeight: "bold",
          }}
        >
          Retry WS
        </button>
      )}
    </div>
  );
};

import React from "react";
import { Shield } from "lucide-react";
import { ConnectionIndicator } from "../common/ConnectionIndicator";
import { WebSocketConnectionStatus } from "../../types/websocket";

interface HeaderProps {
  wsStatus: WebSocketConnectionStatus;
  onReconnectWs?: () => void;
  totalAlerts?: number;
  criticalCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  wsStatus,
  onReconnectWs,
  totalAlerts = 0,
  criticalCount = 0,
}) => {
  return (
    <header
      style={{
        height: "64px",
        background: "rgba(10, 13, 20, 0.95)",
        backdropFilter: "blur(12px)",
        borderBottom: "1px solid var(--border-subtle)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 1.5rem",
        position: "sticky",
        top: 0,
        zIndex: 40,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "0.85rem" }}>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 12px rgba(59, 130, 246, 0.4)",
          }}
        >
          <Shield size={20} color="#fff" />
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ fontWeight: 700, fontSize: "1.05rem", letterSpacing: "0.02em" }}>
              SentinelAI
            </span>
            <span
              style={{
                fontSize: "0.65rem",
                padding: "0.1rem 0.35rem",
                borderRadius: 4,
                background: "rgba(59, 130, 246, 0.15)",
                color: "var(--accent-primary)",
                fontWeight: 600,
                border: "1px solid rgba(59, 130, 246, 0.3)",
              }}
            >
              SOC v1.0
            </span>
          </div>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Passive Network Threat Detection Platform
          </span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "1rem",
            fontSize: "0.8rem",
            color: "var(--text-secondary)",
            paddingRight: "1rem",
            borderRight: "1px solid var(--border-subtle)",
          }}
        >
          <div>
            Total Incidents: <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>{totalAlerts}</span>
          </div>
          {criticalCount > 0 && (
            <div style={{ color: "var(--severity-critical)", fontWeight: 600 }}>
              {criticalCount} Critical Active
            </div>
          )}
        </div>

        <ConnectionIndicator status={wsStatus} onReconnect={onReconnectWs} />
      </div>
    </header>
  );
};

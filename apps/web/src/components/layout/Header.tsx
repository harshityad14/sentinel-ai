import React from "react";
import { Search, Bell } from "lucide-react";
import { ConnectionIndicator } from "../common/ConnectionIndicator";
import { WebSocketConnectionStatus } from "../../types/websocket";

interface HeaderProps {
  activeTabTitle?: string;
  wsStatus: WebSocketConnectionStatus;
  onReconnectWs?: () => void;
  totalAlerts?: number;
  criticalCount?: number;
  searchQuery?: string;
  onSearchChange?: (query: string) => void;
  onNotificationClick?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTabTitle = "Dashboard",
  wsStatus,
  onReconnectWs,
  totalAlerts = 0,
  criticalCount = 0,
  searchQuery = "",
  onSearchChange,
  onNotificationClick,
}) => {
  return (
    <header
      style={{
        height: "60px",
        background: "#ffffff",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 1.75rem",
        position: "sticky",
        top: 0,
        zIndex: 25,
      }}
    >
      {/* Left: Page Title & Subtitle */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.1rem" }}>
        <h1
          style={{
            fontSize: "1.125rem",
            fontWeight: 700,
            color: "#0f172a",
            margin: 0,
            lineHeight: 1.2,
          }}
        >
          {activeTabTitle}
        </h1>
        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
          Real-time AI-powered threat detection and response system
        </span>
      </div>

      {/* Right Controls: Search, Counters, Notifications, Connection */}
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        {/* Search Field */}
        <div style={{ position: "relative", width: "240px" }}>
          <Search
            size={15}
            color="var(--text-muted)"
            style={{
              position: "absolute",
              left: 10,
              top: "50%",
              transform: "translateY(-50%)",
              pointerEvents: "none",
            }}
          />
          <input
            type="text"
            placeholder="Search threats, devices..."
            value={searchQuery}
            onChange={(e) => onSearchChange && onSearchChange(e.target.value)}
            style={{
              width: "100%",
              padding: "0.4rem 0.75rem 0.4rem 2rem",
              fontSize: "0.8rem",
              background: "#f8fafc",
              border: "1px solid var(--border)",
              borderRadius: "6px",
            }}
            aria-label="Search threats and devices"
          />
        </div>

        {/* Quick Incidents Summary */}
        <div
          style={{
            display: "none",
            alignItems: "center",
            gap: "0.85rem",
            fontSize: "0.775rem",
            color: "var(--text-secondary)",
            paddingRight: "0.75rem",
            borderRight: "1px solid var(--border)",
          }}
          className="header-summary"
        >
          <span>
            Total: <strong style={{ color: "#0f172a" }}>{totalAlerts}</strong>
          </span>
          {criticalCount > 0 && (
            <span style={{ color: "var(--severity-critical)", fontWeight: 600 }}>
              {criticalCount} Critical
            </span>
          )}
        </div>

        {/* Notification Bell */}
        <button
          onClick={onNotificationClick}
          aria-label={`Notifications: ${criticalCount} active threats`}
          title={`${criticalCount} active critical threats`}
          style={{
            width: 32,
            height: 32,
            borderRadius: 6,
            border: "1px solid var(--border)",
            background: "#ffffff",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            color: criticalCount > 0 ? "var(--severity-critical)" : "var(--text-secondary)",
            position: "relative",
          }}
        >
          <Bell size={16} />
          {criticalCount > 0 && (
            <span
              style={{
                position: "absolute",
                top: -2,
                right: -2,
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "var(--severity-critical)",
                border: "2px solid #ffffff",
              }}
            />
          )}
        </button>

        {/* Live WebSocket / Polling Connection Indicator */}
        <ConnectionIndicator status={wsStatus} onReconnect={onReconnectWs} />
      </div>
    </header>
  );
};

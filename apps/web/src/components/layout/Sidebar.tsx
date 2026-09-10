import React from "react";
import { AlertTriangle, Network, Radio, BarChart3 } from "lucide-react";

export type NavTab = "alerts" | "flows" | "detections" | "statistics";

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  unresolvedCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  unresolvedCount = 0,
}) => {
  const navItems: { id: NavTab; label: string; icon: React.ReactNode; count?: number }[] = [
    {
      id: "alerts",
      label: "Alerts Feed",
      icon: <AlertTriangle size={18} />,
      count: unresolvedCount > 0 ? unresolvedCount : undefined,
    },
    {
      id: "flows",
      label: "Flow Inspector",
      icon: <Network size={18} />,
    },
    {
      id: "detections",
      label: "Detector Telemetry",
      icon: <Radio size={18} />,
    },
    {
      id: "statistics",
      label: "Threat Radar",
      icon: <BarChart3 size={18} />,
    },
  ];

  return (
    <aside
      style={{
        width: "240px",
        background: "var(--bg-secondary)",
        borderRight: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        height: "calc(100vh - 64px)",
        position: "sticky",
        top: 64,
      }}
    >
      <div style={{ padding: "1.25rem 1rem 0.5rem" }}>
        <span
          style={{
            fontSize: "0.675rem",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.075em",
            color: "var(--text-muted)",
          }}
        >
          SOC Operations
        </span>
      </div>

      <nav style={{ display: "flex", flexDirection: "column", gap: "0.25rem", padding: "0 0.5rem" }}>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "0.65rem 0.85rem",
                borderRadius: "6px",
                background: isActive ? "var(--bg-card-hover)" : "transparent",
                color: isActive ? "var(--accent-primary)" : "var(--text-secondary)",
                fontWeight: isActive ? 600 : 500,
                fontSize: "0.85rem",
                border: "none",
                cursor: "pointer",
                textAlign: "left",
                transition: "all 0.15s ease",
              }}
              aria-current={isActive ? "page" : undefined}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.65rem" }}>
                {item.icon}
                <span>{item.label}</span>
              </div>
              {item.count !== undefined && (
                <span
                  style={{
                    fontSize: "0.7rem",
                    fontWeight: 700,
                    padding: "0.1rem 0.4rem",
                    borderRadius: 9999,
                    backgroundColor: "var(--severity-high-bg)",
                    color: "var(--severity-high)",
                  }}
                >
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div style={{ marginTop: "auto", padding: "1rem", borderTop: "1px solid var(--border-subtle)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
        <p>Passive Boundary: ACTIVE</p>
        <p style={{ marginTop: "0.25rem", color: "var(--severity-resolved)" }}>Zero Injections / No Probes</p>
      </div>
    </aside>
  );
};

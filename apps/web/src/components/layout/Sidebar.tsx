import React from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  Network,
  Server,
  BarChart3,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  Radio,
} from "lucide-react";

export type NavTab = "dashboard" | "threats" | "network" | "assets" | "analytics" | "settings";

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  unresolvedCount?: number;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  unresolvedCount = 0,
  collapsed = false,
  onToggleCollapse,
}) => {
  const navItems: { id: NavTab; label: string; icon: React.ReactNode; count?: number }[] = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: <LayoutDashboard size={18} />,
    },
    {
      id: "threats",
      label: "Threats",
      icon: <ShieldAlert size={18} />,
      count: unresolvedCount > 0 ? unresolvedCount : undefined,
    },
    {
      id: "network",
      label: "Network",
      icon: <Network size={18} />,
    },
    {
      id: "assets",
      label: "Assets",
      icon: <Server size={18} />,
    },
    {
      id: "analytics",
      label: "Analytics",
      icon: <BarChart3 size={18} />,
    },
    {
      id: "settings",
      label: "Settings",
      icon: <Settings size={18} />,
    },
  ];

  return (
    <aside
      style={{
        width: collapsed ? "68px" : "240px",
        background: "#ffffff",
        borderRight: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        height: "100vh",
        position: "sticky",
        top: 0,
        transition: "width 0.2s ease-in-out",
        zIndex: 30,
      }}
      aria-label="Main Navigation Sidebar"
    >
      {/* Top Header / Wordmark */}
      <div
        style={{
          height: "60px",
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          padding: collapsed ? "0 0.5rem" : "0 1rem 0 1.25rem",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.65rem", overflow: "hidden" }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              background: "#1a73e8",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Shield size={18} color="#ffffff" />
          </div>
          {!collapsed && (
            <div style={{ display: "flex", flexDirection: "column" }}>
              <span
                style={{
                  fontWeight: 700,
                  fontSize: "0.95rem",
                  color: "#0f172a",
                  letterSpacing: "-0.01em",
                  lineHeight: 1.1,
                }}
              >
                SentinelAI
              </span>
              <span
                style={{
                  fontSize: "0.675rem",
                  color: "var(--text-muted)",
                  fontWeight: 500,
                }}
              >
                Enterprise SOC
              </span>
            </div>
          )}
        </div>

        {onToggleCollapse && !collapsed && (
          <button
            onClick={onToggleCollapse}
            aria-label="Collapse sidebar"
            title="Collapse sidebar"
            style={{
              width: 26,
              height: 26,
              borderRadius: 5,
              border: "1px solid var(--border)",
              background: "#ffffff",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "var(--text-secondary)",
              transition: "all 0.15s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "#f1f5f9";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "#ffffff";
            }}
          >
            <ChevronLeft size={15} />
          </button>
        )}
      </div>

      {/* Navigation List */}
      <nav
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "0.25rem",
          padding: collapsed ? "1rem 0.5rem" : "1rem 0.75rem",
          flex: 1,
        }}
      >
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              title={collapsed ? item.label : undefined}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: collapsed ? "center" : "space-between",
                padding: collapsed ? "0.65rem" : "0.6rem 0.85rem",
                borderRadius: "6px",
                background: isActive ? "#eff6ff" : "transparent",
                color: isActive ? "#1d4ed8" : "#475569",
                fontWeight: isActive ? 600 : 500,
                fontSize: "0.85rem",
                border: "none",
                cursor: "pointer",
                textAlign: "left",
                transition: "all 0.15s ease",
                position: "relative",
              }}
              aria-current={isActive ? "page" : undefined}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = "#f8fafc";
                  e.currentTarget.style.color = "#0f172a";
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = "transparent";
                  e.currentTarget.style.color = "#475569";
                }
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <span style={{ color: isActive ? "#1d4ed8" : "#64748b", display: "flex" }}>
                  {item.icon}
                </span>
                {!collapsed && <span>{item.label}</span>}
              </div>

              {!collapsed && item.count !== undefined && item.count > 0 && (
                <span
                  style={{
                    fontSize: "0.7rem",
                    fontWeight: 600,
                    padding: "0.1rem 0.4rem",
                    borderRadius: 9999,
                    backgroundColor: "var(--severity-critical-bg)",
                    color: "var(--severity-critical)",
                    border: "1px solid var(--severity-critical-border)",
                  }}
                >
                  {item.count}
                </span>
              )}

              {collapsed && item.count !== undefined && item.count > 0 && (
                <span
                  style={{
                    position: "absolute",
                    top: 4,
                    right: 4,
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    backgroundColor: "var(--severity-critical)",
                  }}
                />
              )}
            </button>
          );
        })}
      </nav>

      {/* Expand Button if Collapsed */}
      {collapsed && onToggleCollapse && (
        <div style={{ padding: "0.5rem", display: "flex", justifyContent: "center" }}>
          <button
            onClick={onToggleCollapse}
            aria-label="Expand sidebar"
            title="Expand sidebar"
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
              color: "var(--text-secondary)",
            }}
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}

      {/* Bottom Area: Passive Invariant & Operator Profile */}
      {!collapsed && (
        <div
          style={{
            marginTop: "auto",
            padding: "0.85rem 1rem",
            borderTop: "1px solid var(--border)",
            background: "#ffffff",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              fontSize: "0.725rem",
              color: "var(--text-muted)",
              marginBottom: "0.5rem",
            }}
          >
            <Radio size={13} color="#16a34a" />
            <span style={{ fontWeight: 600, color: "#16a34a" }}>Passive Boundary: ACTIVE</span>
          </div>
          <div
            style={{
              fontSize: "0.7rem",
              color: "var(--text-muted)",
              lineHeight: 1.3,
            }}
          >
            Zero packet injection / Non-intrusive monitoring
          </div>

          <div
            style={{
              marginTop: "0.75rem",
              paddingTop: "0.65rem",
              borderTop: "1px solid #f1f5f9",
              display: "flex",
              alignItems: "center",
              gap: "0.6rem",
            }}
          >
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: "50%",
                background: "#eff6ff",
                border: "1px solid #bfdbfe",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "#1d4ed8",
              }}
            >
              SA
            </div>
            <div style={{ display: "flex", flexDirection: "column" }}>
              <span style={{ fontSize: "0.775rem", fontWeight: 600, color: "#0f172a" }}>
                SOC Analyst
              </span>
              <span style={{ fontSize: "0.675rem", color: "var(--text-muted)" }}>
                Active Operator
              </span>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};

import React, { useState } from "react";
import { Header } from "./Header";
import { Sidebar, NavTab } from "./Sidebar";
import { WebSocketConnectionStatus } from "../../types/websocket";

interface LayoutProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  wsStatus: WebSocketConnectionStatus;
  onReconnectWs?: () => void;
  totalAlerts?: number;
  criticalCount?: number;
  searchQuery?: string;
  onSearchChange?: (q: string) => void;
  children: React.ReactNode;
}

const TAB_TITLES: Record<NavTab, string> = {
  dashboard: "Dashboard",
  threats: "Security Threats & Incidents",
  network: "Network Flow Telemetry",
  assets: "Asset Posture & Devices",
  analytics: "AI & Threat Analytics",
  settings: "System Status & Invariants",
};

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  onTabChange,
  wsStatus,
  onReconnectWs,
  totalAlerts = 0,
  criticalCount = 0,
  searchQuery,
  onSearchChange,
  children,
}) => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div style={{ minHeight: "100vh", display: "flex", backgroundColor: "var(--bg-primary)" }}>
      {/* Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={onTabChange}
        unresolvedCount={criticalCount}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
      />

      {/* Main Content Area */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          minWidth: 0,
          overflowX: "hidden",
        }}
      >
        {/* Top Header */}
        <Header
          activeTabTitle={TAB_TITLES[activeTab] || "Dashboard"}
          wsStatus={wsStatus}
          onReconnectWs={onReconnectWs}
          totalAlerts={totalAlerts}
          criticalCount={criticalCount}
          searchQuery={searchQuery}
          onSearchChange={onSearchChange}
          onNotificationClick={() => onTabChange("threats")}
        />

        {/* Page Content */}
        <main
          style={{
            flex: 1,
            padding: "1.5rem 2rem",
            overflowY: "auto",
            maxWidth: "1600px",
            width: "100%",
            margin: "0 auto",
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
};

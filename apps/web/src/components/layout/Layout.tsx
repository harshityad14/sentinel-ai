import React from "react";
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
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  onTabChange,
  wsStatus,
  onReconnectWs,
  totalAlerts,
  criticalCount,
  children,
}) => {
  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header
        wsStatus={wsStatus}
        onReconnectWs={onReconnectWs}
        totalAlerts={totalAlerts}
        criticalCount={criticalCount}
      />
      <div style={{ display: "flex", flex: 1 }}>
        <Sidebar
          activeTab={activeTab}
          onTabChange={onTabChange}
          unresolvedCount={criticalCount}
        />
        <main
          style={{
            flex: 1,
            padding: "1.5rem 2rem",
            backgroundColor: "var(--bg-primary)",
            overflowY: "auto",
            maxWidth: "calc(100vw - 240px)",
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
};

import React, { useState } from "react";
import { Layout } from "./components/layout/Layout";
import { NavTab } from "./components/layout/Sidebar";
import { DashboardView } from "./components/dashboard/DashboardView";
import { AlertStatsCards } from "./components/alerts/AlertStatsCards";
import { AlertFilters } from "./components/alerts/AlertFilters";
import { AlertsTable } from "./components/alerts/AlertsTable";
import { AlertDetailDrawer } from "./components/alerts/AlertDetailDrawer";
import { Pagination } from "./components/common/Pagination";
import { FlowsTable } from "./components/flows/FlowsTable";
import { DetectionsTable } from "./components/detections/DetectionsTable";
import { ThreatRadarView } from "./components/statistics/ThreatRadarView";
import { AssetsView } from "./components/assets/AssetsView";
import { SettingsView } from "./components/settings/SettingsView";
import { useAlerts } from "./hooks/useAlerts";
import { useFlows } from "./hooks/useFlows";
import { useDetections } from "./hooks/useDetections";
import { useStats } from "./hooks/useStats";
import { useDashboardData } from "./hooks/useDashboardData";
import { acknowledgeAlert } from "./api/alerts";
import type { SecurityAlertRead } from "./types/alert";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>("dashboard");
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlertRead | null>(null);
  const [globalSearch, setGlobalSearch] = useState<string>("");

  // Alerts Hook with WebSocket Real-Time Updates & Fallback Polling
  const {
    alerts,
    total,
    loading: alertsLoading,
    error: alertsError,
    filters: alertParams,
    wsStatus,
    updateFilters,
    updateStatus,
    refresh,
    reconnectWs,
  } = useAlerts();

  // Flows Hook
  const {
    flows,
    total: flowsTotal,
    loading: flowsLoading,
    error: flowsError,
    params: flowParams,
    setParams: setFlowParams,
  } = useFlows();

  // Detections Hook
  const {
    detections,
    total: detectionsTotal,
    loading: detectionsLoading,
    error: detectionsError,
    params: detectionParams,
    setParams: setDetectionParams,
  } = useDetections();

  // Stats Hook
  const { stats, loading: statsLoading, refetch: refetchStats } = useStats();

  // Dashboard Telemetry & System Status Hook
  const dashboardData = useDashboardData();

  const handlePageChange = (newOffset: number) => {
    updateFilters({ offset: newOffset });
  };

  const handleFlowPageChange = (newOffset: number) => {
    setFlowParams((prev: any) => ({
      ...prev,
      offset: newOffset,
    }));
  };

  const handleDetectionPageChange = (newOffset: number) => {
    setDetectionParams((prev: any) => ({
      ...prev,
      offset: newOffset,
    }));
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await acknowledgeAlert(alertId, "analyst-1", "Acknowledged from Dashboard");
      refresh();
      refetchStats();
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  };

  const handleGlobalSearch = (query: string) => {
    setGlobalSearch(query);
    if (activeTab === "threats") {
      updateFilters({ search: query });
    }
  };

  return (
    <Layout
      activeTab={activeTab}
      onTabChange={setActiveTab}
      wsStatus={wsStatus}
      onReconnectWs={reconnectWs}
      totalAlerts={total}
      criticalCount={stats?.by_severity?.["CRITICAL"] || 0}
      searchQuery={globalSearch}
      onSearchChange={handleGlobalSearch}
    >
      {/* 1. DASHBOARD TAB */}
      {activeTab === "dashboard" && (
        <DashboardView
          alerts={alerts}
          stats={stats}
          dashboardData={dashboardData}
          onSelectAlert={(a) => setSelectedAlert(a)}
          onNavigateTab={(tab) => setActiveTab(tab)}
          onAcknowledgeAlert={handleAcknowledgeAlert}
          searchFilter={globalSearch}
        />
      )}

      {/* 2. THREATS TAB (Alerts Feed) */}
      {activeTab === "threats" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <AlertStatsCards stats={stats} />

          <AlertFilters
            filters={alertParams}
            onFilterChange={(newFilters) => updateFilters(newFilters)}
            onReset={() =>
              updateFilters({
                threat_class: undefined,
                severity: undefined,
                status: undefined,
                min_risk: undefined,
                search: undefined,
                offset: 0,
              })
            }
          />

          <AlertsTable
            alerts={alerts}
            total={total}
            loading={alertsLoading}
            error={alertsError}
            limit={alertParams.limit || 25}
            offset={alertParams.offset || 0}
            sortBy={alertParams.sort_by}
            sortDesc={alertParams.sort_desc}
            onSort={(field) =>
              updateFilters({ sort_by: field, sort_desc: !alertParams.sort_desc })
            }
            onPageChange={handlePageChange}
            onSelectAlert={(a) => setSelectedAlert(a)}
            onRetry={refresh}
          />
        </div>
      )}

      {/* 3. NETWORK TAB (Flows Telemetry) */}
      {activeTab === "network" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h2 style={{ fontSize: "1.15rem", fontWeight: 700, color: "#0f172a", margin: 0 }}>
                Network Flow Telemetry
              </h2>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                Passive packet inspection and reconstructed directional network sessions
              </span>
            </div>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {flowsTotal.toLocaleString()} total captured flows
            </span>
          </div>

          <div
            className="glass-panel"
            style={{
              overflow: "hidden",
            }}
          >
            <FlowsTable flows={flows} loading={flowsLoading} error={flowsError} />
            {flowsTotal > 0 && (
              <div style={{ padding: "0.5rem 1rem", borderTop: "1px solid var(--border)" }}>
                <Pagination
                  total={flowsTotal}
                  limit={flowParams.limit || 50}
                  offset={flowParams.offset || 0}
                  onPageChange={handleFlowPageChange}
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. ASSETS TAB */}
      {activeTab === "assets" && (
        <AssetsView
          entities={dashboardData.entities}
          alerts={alerts}
          loading={dashboardData.loading}
          onSelectEntity={(ip) => {
            setActiveTab("threats");
            updateFilters({ search: ip });
          }}
          onRefresh={dashboardData.refetch}
        />
      )}

      {/* 5. ANALYTICS TAB (Threat Radar & Detector Telemetry) */}
      {activeTab === "analytics" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <div>
            <h2 style={{ fontSize: "1.15rem", fontWeight: 700, color: "#0f172a", margin: 0 }}>
              Threat Radar & Detection Telemetry
            </h2>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Statistical distributions, rule engine telemetry, and anomaly signals
            </span>
          </div>

          <ThreatRadarView stats={stats} loading={statsLoading} />

          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "0.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
                Raw Detector Signals
              </h3>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                {detectionsTotal.toLocaleString()} anomaly detections recorded
              </span>
            </div>

            <div className="glass-panel" style={{ overflow: "hidden" }}>
              <DetectionsTable
                detections={detections}
                loading={detectionsLoading}
                error={detectionsError}
              />
              {detectionsTotal > 0 && (
                <div style={{ padding: "0.5rem 1rem", borderTop: "1px solid var(--border)" }}>
                  <Pagination
                    total={detectionsTotal}
                    limit={detectionParams.limit || 50}
                    offset={detectionParams.offset || 0}
                    onPageChange={handleDetectionPageChange}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. SETTINGS TAB */}
      {activeTab === "settings" && (
        <SettingsView wsStatus={wsStatus} onReconnectWs={reconnectWs} />
      )}

      {/* Alert Detail Drawer (Accessible across all views) */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onUpdateStatus={async (alertId, newStatus, operator, notes) => {
          await updateStatus(alertId, newStatus, operator, notes);
          if (selectedAlert && selectedAlert.alert_id === alertId) {
            setSelectedAlert({
              ...selectedAlert,
              status: newStatus,
              assigned_to: operator,
              updated_at: new Date().toISOString(),
            });
          }
          refetchStats();
        }}
      />
    </Layout>
  );
};

export default App;

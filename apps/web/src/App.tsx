import React, { useState } from 'react';
import { Layout } from './components/layout/Layout';
import { AlertStatsCards } from './components/alerts/AlertStatsCards';
import { AlertFilters } from './components/alerts/AlertFilters';
import { AlertsTable } from './components/alerts/AlertsTable';
import { AlertDetailDrawer } from './components/alerts/AlertDetailDrawer';
import { Pagination } from './components/common/Pagination';
import { FlowsTable } from './components/flows/FlowsTable';
import { DetectionsTable } from './components/detections/DetectionsTable';
import { ThreatRadarView } from './components/statistics/ThreatRadarView';
import { useAlerts } from './hooks/useAlerts';
import { useFlows } from './hooks/useFlows';
import { useDetections } from './hooks/useDetections';
import { useStats } from './hooks/useStats';
import type { SecurityAlertRead } from './types/alert';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'alerts' | 'flows' | 'detections' | 'statistics'>('alerts');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlertRead | null>(null);

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
  const { stats, loading: statsLoading } = useStats();

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

  return (
    <Layout
      activeTab={activeTab}
      onTabChange={setActiveTab}
      wsStatus={wsStatus}
      onReconnectWs={reconnectWs}
      totalAlerts={total}
      criticalCount={stats?.by_severity?.['CRITICAL'] || 0}
    >
      {/* ALERTS TAB */}
      {activeTab === 'alerts' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <AlertStatsCards stats={stats} />

          <AlertFilters
            filters={alertParams}
            onFilterChange={(newFilters) => updateFilters(newFilters)}
            onReset={() => updateFilters({ threat_class: undefined, severity: undefined, status: undefined, min_risk: undefined, search: undefined, offset: 0 })}
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
            onSort={(field) => updateFilters({ sort_by: field, sort_desc: !alertParams.sort_desc })}
            onPageChange={handlePageChange}
            onSelectAlert={(a) => setSelectedAlert(a)}
            onRetry={refresh}
          />
        </div>
      )}

      {/* FLOWS TAB */}
      {activeTab === 'flows' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
              Network Flows Ingestion Telemetry
            </h2>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              {flowsTotal.toLocaleString()} total captured flows
            </span>
          </div>

          <div
            style={{
              background: 'var(--bg-card)',
              borderRadius: '8px',
              border: '1px solid var(--border)',
              overflow: 'hidden',
            }}
          >
            <FlowsTable flows={flows} loading={flowsLoading} error={flowsError} />
            {flowsTotal > 0 && (
              <div style={{ padding: '0.5rem 1rem', borderTop: '1px solid var(--border)' }}>
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

      {/* DETECTIONS TAB */}
      {activeTab === 'detections' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
              AI & Rule Engine Detections
            </h2>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              {detectionsTotal.toLocaleString()} total anomaly signals
            </span>
          </div>

          <div
            style={{
              background: 'var(--bg-card)',
              borderRadius: '8px',
              border: '1px solid var(--border)',
              overflow: 'hidden',
            }}
          >
            <DetectionsTable detections={detections} loading={detectionsLoading} error={detectionsError} />
            {detectionsTotal > 0 && (
              <div style={{ padding: '0.5rem 1rem', borderTop: '1px solid var(--border)' }}>
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
      )}

      {/* STATISTICS TAB */}
      {activeTab === 'statistics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
              Threat Radar & Security Metrics
            </h2>
          </div>

          <ThreatRadarView stats={stats} loading={statsLoading} />
        </div>
      )}

      {/* Alert Detail Drawer */}
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
        }}
      />
    </Layout>
  );
};

export default App;

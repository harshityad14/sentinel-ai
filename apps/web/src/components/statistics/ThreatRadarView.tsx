import React from 'react';
import type { SecurityAlertStats } from '../../types/alert';

interface ThreatRadarViewProps {
  stats: SecurityAlertStats | null;
  loading: boolean;
}

export const ThreatRadarView: React.FC<ThreatRadarViewProps> = ({ stats, loading }) => {
  if (loading && !stats) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
        Aggregating threat telemetry...
      </div>
    );
  }

  if (!stats) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        No threat statistics available.
      </div>
    );
  }

  const severityEntries = Object.entries(stats.by_severity || {}) as [string, number][];
  const statusEntries = Object.entries(stats.by_status || {}) as [string, number][];
  const maxSeverityCount = Math.max(...severityEntries.map(([_, v]) => v), 1);
  const unresolved = stats.unresolved_alerts ?? (stats.by_status?.['NEW'] || 0) + (stats.by_status?.['ACTIVE'] || 0);
  const meanRisk = stats.avg_risk_score ?? stats.mean_risk_score ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <div className="glass-panel" style={{ padding: '1.15rem 1.25rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Total Alerts Recorded
          </span>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: '#0f172a', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
            {stats.total_alerts.toLocaleString()}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.15rem 1.25rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Unresolved Threats
          </span>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: 'var(--warning)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
            {unresolved.toLocaleString()}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.15rem 1.25rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Mean Risk Score
          </span>
          <div style={{ fontSize: '1.65rem', fontWeight: 700, color: 'var(--accent-primary)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
            {meanRisk.toFixed(1)} / 100
          </div>
        </div>
      </div>

      {/* Distribution Bars */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
        {/* Severity Distribution */}
        <div className="glass-panel" style={{ padding: '1.25rem 1.5rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#0f172a', marginBottom: '1rem' }}>
            Threat Severity Distribution
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {severityEntries.map(([sev, count]) => {
              const pct = (count / maxSeverityCount) * 100;
              let barColor = 'var(--accent-primary)';
              if (sev === 'CRITICAL') barColor = 'var(--severity-critical)';
              else if (sev === 'HIGH') barColor = 'var(--severity-high)';
              else if (sev === 'MEDIUM') barColor = 'var(--severity-medium)';
              else if (sev === 'LOW') barColor = 'var(--severity-low)';

              return (
                <div key={sev} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.775rem' }}>
                    <span style={{ fontWeight: 600, color: '#0f172a' }}>{sev}</span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {count} ({((count / (stats.total_alerts || 1)) * 100).toFixed(0)}%)
                    </span>
                  </div>
                  <div style={{ height: '8px', background: '#f1f5f9', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${pct}%`,
                        background: barColor,
                        borderRadius: '4px',
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Status Breakdown */}
        <div className="glass-panel" style={{ padding: '1.25rem 1.5rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#0f172a', marginBottom: '1rem' }}>
            Investigation Status
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {statusEntries.map(([status, count]) => (
              <div
                key={status}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.5rem 0.75rem',
                  background: '#f8fafc',
                  borderRadius: '6px',
                  border: '1px solid var(--border)',
                }}
              >
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#0f172a' }}>
                  {status}
                </span>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

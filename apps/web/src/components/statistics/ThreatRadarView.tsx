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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Alerts Recorded</span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.25rem' }}>
            {stats.total_alerts.toLocaleString()}
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Unresolved Threats</span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--warning)', marginTop: '0.25rem' }}>
            {unresolved.toLocaleString()}
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Mean Risk Score</span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--primary-glow)', marginTop: '0.25rem' }}>
            {meanRisk.toFixed(1)} / 100
          </div>
        </div>
      </div>

      {/* Distribution Bars */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Severity Distribution */}
        <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '1rem' }}>
            Threat Severity Distribution
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {severityEntries.map(([sev, count]) => {
              const pct = (count / maxSeverityCount) * 100;
              let barColor = 'var(--accent)';
              if (sev === 'CRITICAL') barColor = 'var(--danger)';
              else if (sev === 'HIGH') barColor = '#fb923c';
              else if (sev === 'MEDIUM') barColor = 'var(--warning)';

              return (
                <div key={sev} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{sev}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{count} ({((count / (stats.total_alerts || 1)) * 100).toFixed(0)}%)</span>
                  </div>
                  <div style={{ height: '8px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', overflow: 'hidden' }}>
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
        <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '1rem' }}>
            Investigation Status
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {statusEntries.map(([status, count]) => (
              <div
                key={status}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.5rem 0.75rem',
                  background: 'rgba(255, 255, 255, 0.02)',
                  borderRadius: '6px',
                  border: '1px solid var(--border)',
                }}
              >
                <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-main)' }}>
                  {status}
                </span>
                <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--primary-glow)' }}>
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

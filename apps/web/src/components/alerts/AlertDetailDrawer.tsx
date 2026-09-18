import React, { useState } from 'react';
import type { SecurityAlertRead, AlertStatus } from '../../types/alert';
import { Badge } from '../common/Badge';
import { RiskGauge } from '../common/RiskGauge';
import { StatusPill } from '../common/StatusPill';
import { EvidenceViewer } from './EvidenceViewer';
import { SignalList } from './SignalList';
import { LifecycleModal } from './LifecycleModal';
import { AIAnalystPanel } from '../ai/AIAnalystPanel';
import { Sparkles, X } from 'lucide-react';

interface AlertDetailDrawerProps {
  alert: SecurityAlertRead | null;
  onClose: () => void;
  onUpdateStatus: (alertId: string, newStatus: AlertStatus, operator: string, notes: string) => Promise<void>;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  onClose,
  onUpdateStatus,
}) => {
  const [activeTab, setActiveTab] = useState<'details' | 'evidence' | 'signals' | 'audit' | 'ai_analyst'>('details');
  const [isLifecycleModalOpen, setIsLifecycleModalOpen] = useState(false);

  if (!alert) return null;

  const riskValue =
    typeof alert.risk_score === "object" && alert.risk_score !== null
      ? (alert.risk_score as any).score || 0
      : typeof alert.risk_score === "number"
      ? alert.risk_score
      : 0;

  const createdAtText = alert.created_at || alert.first_seen || new Date().toISOString();

  return (
    <>
      <div
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(640px, 92vw)',
          background: '#ffffff',
          borderLeft: '1px solid var(--border)',
          boxShadow: 'var(--shadow-drawer)',
          zIndex: 100,
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideIn 0.2s ease-out',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.15rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            background: '#ffffff',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <Badge severity={alert.severity}>{alert.severity}</Badge>
              <StatusPill status={alert.status} />
              <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
                {new Date(createdAtText).toLocaleString()}
              </span>
            </div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#0f172a', marginTop: '0.25rem' }}>
              {alert.title || alert.threat_class}
            </h2>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              ID: {alert.alert_id}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close alert drawer"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.25rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Action Toolbar */}
        <div
          style={{
            padding: '0.65rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            background: '#f8fafc',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.5rem',
          }}
        >
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => setActiveTab('details')}
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.8rem',
                borderRadius: '5px',
                border: 'none',
                background: activeTab === 'details' ? '#eff6ff' : 'transparent',
                color: activeTab === 'details' ? '#1d4ed8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: activeTab === 'details' ? 600 : 500,
              }}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab('evidence')}
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.8rem',
                borderRadius: '5px',
                border: 'none',
                background: activeTab === 'evidence' ? '#eff6ff' : 'transparent',
                color: activeTab === 'evidence' ? '#1d4ed8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: activeTab === 'evidence' ? 600 : 500,
              }}
            >
              Evidence ({Object.keys(alert.evidence || {}).length})
            </button>
            <button
              onClick={() => setActiveTab('signals')}
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.8rem',
                borderRadius: '5px',
                border: 'none',
                background: activeTab === 'signals' ? '#eff6ff' : 'transparent',
                color: activeTab === 'signals' ? '#1d4ed8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: activeTab === 'signals' ? 600 : 500,
              }}
            >
              Signals ({(alert.detection_signals || []).length})
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.8rem',
                borderRadius: '5px',
                border: 'none',
                background: activeTab === 'audit' ? '#eff6ff' : 'transparent',
                color: activeTab === 'audit' ? '#1d4ed8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: activeTab === 'audit' ? 600 : 500,
              }}
            >
              Audit Trail
            </button>
            <button
              onClick={() => setActiveTab('ai_analyst')}
              style={{
                padding: '0.35rem 0.65rem',
                fontSize: '0.8rem',
                borderRadius: '5px',
                border: '1px solid #bfdbfe',
                background: activeTab === 'ai_analyst' ? '#eff6ff' : '#ffffff',
                color: '#1d4ed8',
                cursor: 'pointer',
                fontWeight: activeTab === 'ai_analyst' ? 600 : 500,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem',
              }}
            >
              <Sparkles size={12} color="#1d4ed8" />
              AI Analyst
            </button>
          </div>

          <button
            onClick={() => setIsLifecycleModalOpen(true)}
            className="btn btn-primary btn-sm"
          >
            Update Lifecycle
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '1.25rem 1.5rem', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '1.25rem', background: '#f8fafc' }}>
          {activeTab === 'details' && (
            <>
              {/* Risk & Explanation Panel */}
              <div
                className="glass-panel"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1.25rem',
                  padding: '1.15rem',
                }}
              >
                <div style={{ flexShrink: 0 }}>
                  <RiskGauge score={riskValue} size={80} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
                    Calculated Threat Risk
                  </span>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#0f172a', lineHeight: 1.45 }}>
                    {alert.explanation || alert.description || 'Anomaly observed across passive network telemetry matching correlated threat signatures.'}
                  </p>
                </div>
              </div>

              {/* Entity Context Table */}
              <div
                className="glass-panel"
                style={{
                  padding: '1.15rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
              >
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Network Entities
                </span>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Source IP</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0f172a', fontSize: '0.9rem' }}>
                      {alert.source_ip || 'N/A'}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Destination IP</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0f172a', fontSize: '0.9rem' }}>
                      {alert.destination_ip || 'N/A'}
                    </div>
                  </div>
                </div>

                {alert.correlation_id && (
                  <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.65rem' }}>
                    <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Correlation Group ID</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.775rem', color: '#1d4ed8' }}>
                      {alert.correlation_id}
                    </div>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Matrix Mapping */}
              <div
                className="glass-panel"
                style={{
                  padding: '1.15rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                }}
              >
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  MITRE ATT&CK® Mappings
                </span>
                {alert.mitre_tactics && alert.mitre_tactics.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                    {alert.mitre_tactics.map((tactic, i) => (
                      <span
                        key={i}
                        style={{
                          background: '#eff6ff',
                          border: '1px solid #bfdbfe',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.725rem',
                          color: '#1d4ed8',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 600,
                        }}
                      >
                        {tactic}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    No specific MITRE ATT&CK tactics mapped to this alert.
                  </span>
                )}
              </div>
            </>
          )}

          {activeTab === 'evidence' && (
            <div className="glass-panel" style={{ padding: '1.15rem' }}>
              <EvidenceViewer evidence={alert.evidence} />
            </div>
          )}

          {activeTab === 'signals' && (
            <div className="glass-panel" style={{ padding: '1.15rem' }}>
              <SignalList signals={alert.detection_signals || []} />
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="glass-panel" style={{ padding: '1.15rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Passive Security & Lifecycle Audit
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Created At</span>
                  <span style={{ color: '#0f172a', fontFamily: 'var(--font-mono)' }}>{alert.created_at}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Last Updated</span>
                  <span style={{ color: '#0f172a', fontFamily: 'var(--font-mono)' }}>{alert.updated_at}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Assigned Analyst</span>
                  <span style={{ color: '#0f172a', fontWeight: 500 }}>{alert.assigned_to || 'Unassigned'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Passive Monitoring Invariant</span>
                  <span style={{ color: '#16a34a', fontWeight: 600 }}>Active (Read-Only)</span>
                </div>
              </div>

              {alert.comments && alert.comments.length > 0 && (
                <div style={{ marginTop: '0.75rem' }}>
                  <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Analyst Notes</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.35rem' }}>
                    {alert.comments.map((c: any, i: number) => (
                      <div key={i} style={{ background: '#f8fafc', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                          <span>{c.author}</span>
                          <span>{c.timestamp ? new Date(c.timestamp).toLocaleString() : ''}</span>
                        </div>
                        <div style={{ fontSize: '0.8rem', color: '#0f172a', marginTop: '0.2rem' }}>{c.text}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai_analyst' && (
            <AIAnalystPanel alertId={alert.alert_id} alert={alert} />
          )}
        </div>
      </div>

      {isLifecycleModalOpen && (
        <LifecycleModal
          isOpen={isLifecycleModalOpen}
          onClose={() => setIsLifecycleModalOpen(false)}
          currentStatus={alert.status}
          alertId={alert.alert_id}
          onUpdateStatus={async (newStatus, operator, notes) => {
            await onUpdateStatus(alert.alert_id, newStatus, operator, notes);
          }}
        />
      )}
    </>
  );
};

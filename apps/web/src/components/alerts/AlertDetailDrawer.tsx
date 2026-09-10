import React, { useState } from 'react';
import type { SecurityAlertRead, AlertStatus } from '../../types/alert';
import { Badge } from '../common/Badge';
import { RiskGauge } from '../common/RiskGauge';
import { StatusPill } from '../common/StatusPill';
import { EvidenceViewer } from './EvidenceViewer';
import { SignalList } from './SignalList';
import { LifecycleModal } from './LifecycleModal';
import { AIAnalystPanel } from '../ai/AIAnalystPanel';
import { Sparkles } from 'lucide-react';

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
      ? alert.risk_score.score
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
          width: 'min(640px, 90vw)',
          background: 'var(--bg-surface)',
          borderLeft: '1px solid var(--border)',
          boxShadow: '-8px 0 32px rgba(0, 0, 0, 0.5)',
          zIndex: 100,
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideIn 0.2s ease-out',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            background: 'var(--bg-card)',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <Badge variant={alert.severity.toLowerCase() as any}>{alert.severity}</Badge>
              <StatusPill status={alert.status} />
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {new Date(createdAtText).toLocaleString()}
              </span>
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', marginTop: '0.25rem' }}>
              {alert.title || alert.threat_class}
            </h2>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
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
              fontSize: '1.5rem',
              cursor: 'pointer',
              padding: '0.25rem',
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        {/* Action Toolbar */}
        <div
          style={{
            padding: '0.75rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            background: 'rgba(255, 255, 255, 0.01)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => setActiveTab('details')}
              style={{
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: '4px',
                border: 'none',
                background: activeTab === 'details' ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                color: activeTab === 'details' ? 'var(--primary-glow)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontWeight: activeTab === 'details' ? 600 : 400,
              }}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab('evidence')}
              style={{
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: '4px',
                border: 'none',
                background: activeTab === 'evidence' ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                color: activeTab === 'evidence' ? 'var(--primary-glow)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontWeight: activeTab === 'evidence' ? 600 : 400,
              }}
            >
              Evidence ({Object.keys(alert.evidence || {}).length})
            </button>
            <button
              onClick={() => setActiveTab('signals')}
              style={{
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: '4px',
                border: 'none',
                background: activeTab === 'signals' ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                color: activeTab === 'signals' ? 'var(--primary-glow)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontWeight: activeTab === 'signals' ? 600 : 400,
              }}
            >
              Signals ({(alert.detection_signals || []).length})
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              style={{
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: '4px',
                border: 'none',
                background: activeTab === 'audit' ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                color: activeTab === 'audit' ? 'var(--primary-glow)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontWeight: activeTab === 'audit' ? 600 : 400,
              }}
            >
              Audit Trail
            </button>
            <button
              onClick={() => setActiveTab('ai_analyst')}
              style={{
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: '4px',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                background: activeTab === 'ai_analyst' ? 'rgba(59, 130, 246, 0.25)' : 'rgba(59, 130, 246, 0.08)',
                color: activeTab === 'ai_analyst' ? '#60a5fa' : '#93c5fd',
                cursor: 'pointer',
                fontWeight: activeTab === 'ai_analyst' ? 600 : 500,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem',
              }}
            >
              <Sparkles size={13} />
              AI Analyst
            </button>
          </div>

          <button
            onClick={() => setIsLifecycleModalOpen(true)}
            style={{
              padding: '0.35rem 0.75rem',
              fontSize: '0.85rem',
              fontWeight: 600,
              borderRadius: '6px',
              border: '1px solid var(--border)',
              background: 'var(--primary)',
              color: 'white',
              cursor: 'pointer',
            }}
          >
            Update Lifecycle
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {activeTab === 'details' && (
            <>
              {/* Risk & Explanation Panel */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1.5rem',
                  background: 'var(--bg-card)',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                }}
              >
                <div style={{ flexShrink: 0 }}>
                  <RiskGauge score={riskValue} size={84} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Calculated Threat Risk
                  </span>
                  <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-main)', lineHeight: 1.4 }}>
                    {alert.explanation || 'Anomaly observed across passive network telemetry matching correlated threat signatures.'}
                  </p>
                </div>
              </div>

              {/* Entity Context Table */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
              >
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Network Entities
                </span>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Source IP</span>
                    <div style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-main)', fontSize: '0.95rem' }}>
                      {alert.source_ip || 'N/A'}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Destination IP</span>
                    <div style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-main)', fontSize: '0.95rem' }}>
                      {alert.destination_ip || 'N/A'}
                    </div>
                  </div>
                </div>

                {alert.correlation_id && (
                  <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Correlation Group ID</span>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--primary-glow)' }}>
                      {alert.correlation_id}
                    </div>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Matrix Mapping */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                }}
              >
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  MITRE ATT&CK® Mappings
                </span>
                {alert.mitre_tactics && alert.mitre_tactics.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {alert.mitre_tactics.map((tactic, i) => (
                      <span
                        key={i}
                        style={{
                          background: 'rgba(99, 102, 241, 0.1)',
                          border: '1px solid rgba(99, 102, 241, 0.3)',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          color: 'var(--primary-glow)',
                          fontFamily: 'monospace',
                        }}
                      >
                        {tactic}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                    No specific MITRE ATT&CK tactics mapped to this alert.
                  </span>
                )}
              </div>
            </>
          )}

          {activeTab === 'evidence' && (
            <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <EvidenceViewer evidence={alert.evidence} />
            </div>
          )}

          {activeTab === 'signals' && (
            <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <SignalList signals={alert.detection_signals || []} />
            </div>
          )}

          {activeTab === 'audit' && (
            <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Passive Security & Lifecycle Audit
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Created At</span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>{alert.created_at}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Last Updated</span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>{alert.updated_at}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Assigned Analyst</span>
                  <span style={{ color: 'var(--text-main)' }}>{alert.assigned_to || 'Unassigned'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Passive Monitoring Invariant</span>
                  <span style={{ color: 'var(--success)' }}>Active (Read-Only)</span>
                </div>
              </div>

              {alert.comments && alert.comments.length > 0 && (
                <div style={{ marginTop: '0.75rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Analyst Notes</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.35rem' }}>
                    {alert.comments.map((c: any, i: number) => (
                      <div key={i} style={{ background: 'rgba(255,255,255,0.02)', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          <span>{c.author}</span>
                          <span>{c.timestamp ? new Date(c.timestamp).toLocaleString() : ''}</span>
                        </div>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-main)', marginTop: '0.2rem' }}>{c.text}</div>
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

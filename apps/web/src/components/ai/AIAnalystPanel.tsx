import React from 'react';
import { useAIAnalyst } from '../../hooks/useAIAnalyst';
import { IncidentSummaryCard } from './IncidentSummaryCard';
import { EvidenceCitations } from './EvidenceCitations';
import { InvestigationSteps } from './InvestigationSteps';
import { UncertaintyBadge } from './UncertaintyBadge';
import { AnalystChat } from './AnalystChat';
import type { SecurityAlertRead } from '../../types/alert';

interface AIAnalystPanelProps {
  alertId: string;
  alert: SecurityAlertRead;
}

export const AIAnalystPanel: React.FC<AIAnalystPanelProps> = ({ alertId, alert }) => {
  const {
    report,
    loading,
    error,
    analyze,
    chatMessages,
    chatLoading,
    chatError,
    ask,
  } = useAIAnalyst(alertId);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        padding: '1.25rem 1.5rem',
        overflowY: 'auto',
      }}
    >
      {/* Initial state: Not yet generated */}
      {!report && !loading && (
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '1rem',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              background: 'rgba(59, 130, 246, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.5rem',
            }}
          >
            ✨
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)', margin: '0 0 0.4rem 0' }}>
              GenAI Security Analyst Copilot
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: 0, maxWidth: '420px', lineHeight: 1.4 }}>
              Generate grounded executive summaries, technical threat assessments, and prioritized investigation steps for alert {alert.threat_class}.
            </p>
          </div>
          <button
            onClick={analyze}
            style={{
              background: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              padding: '0.6rem 1.25rem',
              fontSize: '0.9rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginTop: '0.5rem',
            }}
          >
            <span>Analyze Alert</span>
          </button>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '3rem 2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '1rem',
          }}
        >
          <div
            style={{
              width: '32px',
              height: '32px',
              border: '3px solid rgba(59, 130, 246, 0.2)',
              borderTopColor: '#3b82f6',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
            }}
          />
          <div style={{ fontSize: '0.9rem', color: 'var(--text-main)', fontWeight: 500 }}>
            Grounding analysis in telemetry...
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Retrieving flow sessions, checking evidence thresholds, and verifying attack stage.
          </div>
        </div>
      )}

      {/* Error alert */}
      {error && (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            padding: '0.75rem 1rem',
            color: '#f87171',
            fontSize: '0.85rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>{error}</span>
          <button
            onClick={analyze}
            style={{
              background: 'transparent',
              border: '1px solid #f87171',
              borderRadius: '4px',
              color: '#f87171',
              padding: '0.2rem 0.6rem',
              fontSize: '0.75rem',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Fallback Banner */}
      {report && report.is_fallback && (
        <div
          style={{
            background: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
            borderRadius: '6px',
            padding: '0.6rem 1rem',
            color: '#fbbf24',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>⚠️</span>
          <span>
            <strong>Local Heuristic Synthesis:</strong> {report.fallback_reason || 'Remote LLM provider offline. Report synthesized deterministically from alert evidence.'}
          </span>
        </div>
      )}

      {/* Completed Report Content */}
      {report && (
        <>
          <IncidentSummaryCard report={report} />
          <EvidenceCitations citations={report.evidence_citations} />
          <InvestigationSteps steps={report.recommended_investigation_steps} />
          <UncertaintyBadge uncertainties={report.uncertainties} />
          <AnalystChat
            messages={chatMessages}
            loading={chatLoading}
            error={chatError}
            onSendMessage={ask}
          />
        </>
      )}
    </div>
  );
};

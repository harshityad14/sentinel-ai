import React from 'react';
import type { AlertAnalysisReport } from '../../types/ai_analyst';

interface IncidentSummaryCardProps {
  report: AlertAnalysisReport;
}

export const IncidentSummaryCard: React.FC<IncidentSummaryCardProps> = ({ report }) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
        background: 'var(--bg-card)',
        padding: '1.25rem',
        borderRadius: '8px',
        border: '1px solid var(--border)',
      }}
    >
      {/* Header: Title & Stage */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
          Incident Summary & Analysis
        </h3>
        <span
          style={{
            fontSize: '0.75rem',
            padding: '0.2rem 0.6rem',
            borderRadius: '12px',
            background: 'rgba(59, 130, 246, 0.15)',
            color: '#60a5fa',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            fontWeight: 500,
          }}
        >
          Stage: {report.attack_stage.stage_name} ({Math.round(report.attack_stage.confidence * 100)}% conf)
        </span>
      </div>

      {/* Executive Summary */}
      <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-main)', lineHeight: 1.5 }}>
        {report.executive_summary}
      </p>

      {/* Threat Assessment & Reasoning */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          Analytical Assessment (Model Inference)
        </div>
        <div
          style={{
            fontSize: '0.85rem',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
            padding: '0.75rem',
            background: 'rgba(0, 0, 0, 0.2)',
            borderRadius: '6px',
            borderLeft: '3px solid #3b82f6',
          }}
        >
          {report.threat_assessment} {report.threat_reasoning}
        </div>
      </div>

      {/* MITRE Explanation */}
      {report.mitre_explanation && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <strong style={{ color: 'var(--text-main)' }}>Framework Mapping: </strong>
          {report.mitre_explanation}
        </div>
      )}

      {/* Verified Observed Facts */}
      {report.observed_facts && report.observed_facts.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Verified Observed Facts
          </div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.85rem', color: 'var(--text-main)', lineHeight: 1.4 }}>
            {report.observed_facts.map((fact, i) => (
              <li key={i} style={{ marginBottom: '0.25rem' }}>
                {fact}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

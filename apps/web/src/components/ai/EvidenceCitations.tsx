import React from 'react';
import type { EvidenceCitation } from '../../types/ai_analyst';

interface EvidenceCitationsProps {
  citations: EvidenceCitation[];
}

export const EvidenceCitations: React.FC<EvidenceCitationsProps> = ({ citations }) => {
  if (!citations || citations.length === 0) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
        Grounded Evidence Citations ({citations.length})
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '0.75rem',
        }}
      >
        {citations.map((c, i) => (
          <div
            key={c.citation_id || i}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.35rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#3b82f6', fontFamily: 'monospace' }}>
                {c.citation_id}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {c.detector_name}
              </span>
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-main)', fontWeight: 500 }}>
              {c.feature_name ? `Feature: ${c.feature_name}` : 'Observed Anomaly'}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Value: <strong style={{ color: 'var(--text-main)' }}>{String(c.observed_value)}</strong>
              {c.threshold_value !== undefined && c.threshold_value !== null && (
                <span> (Threshold: {String(c.threshold_value)})</span>
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem', lineHeight: 1.3 }}>
              {c.relevance}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

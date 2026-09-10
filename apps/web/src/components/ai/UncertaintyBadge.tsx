import React from 'react';
import type { UncertaintyIndicator } from '../../types/ai_analyst';

interface UncertaintyBadgeProps {
  uncertainties: UncertaintyIndicator[];
}

export const UncertaintyBadge: React.FC<UncertaintyBadgeProps> = ({ uncertainties }) => {
  if (!uncertainties || uncertainties.length === 0) return null;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
        background: 'rgba(245, 158, 11, 0.08)',
        border: '1px solid rgba(245, 158, 11, 0.25)',
        borderRadius: '6px',
        padding: '0.75rem 1rem',
      }}
    >
      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fbbf24', textTransform: 'uppercase' }}>
        Declared Telemetry Gaps & Uncertainties ({uncertainties.length})
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {uncertainties.map((u, i) => (
          <div key={i} style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
            <strong style={{ color: 'var(--text-main)' }}>{u.aspect}: </strong>
            {u.reason}
            {u.recommended_telemetry && (
              <div style={{ fontSize: '0.75rem', color: '#60a5fa', marginTop: '0.15rem' }}>
                Recommended Telemetry: {u.recommended_telemetry}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

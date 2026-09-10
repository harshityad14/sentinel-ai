import React from 'react';
import type { DetectionSignal } from '../../types/alert';
import { Badge } from '../common/Badge';

interface SignalListProps {
  signals: DetectionSignal[];
}

export const SignalList: React.FC<SignalListProps> = ({ signals }) => {
  if (!signals || signals.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No individual detector signals attached.</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
      {signals.map((sig, idx) => (
        <div
          key={idx}
          style={{
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '0.625rem 0.75rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                {sig.detector_name || sig.detector_type}
              </span>
              <Badge variant={typeof sig.severity === 'string' ? sig.severity.toLowerCase() : 'info'}>
                {sig.severity}
              </Badge>
            </div>
            {(sig as any).mitre_technique && (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                MITRE: <code style={{ color: 'var(--primary-glow)' }}>{(sig as any).mitre_technique}</code>
              </span>
            )}
          </div>

          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent)' }}>
              {(sig.confidence * 100).toFixed(1)}% Conf
            </span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              {new Date(sig.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};

import React from 'react';
import type { DetectionResultRead } from '../../types/detection';
import { Badge } from '../common/Badge';
import { EmptyState } from '../common/EmptyState';

interface DetectionsTableProps {
  detections: DetectionResultRead[];
  loading: boolean;
  error: string | null;
}

export const DetectionsTable: React.FC<DetectionsTableProps> = ({ detections, loading, error }) => {
  if (loading && detections.length === 0) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
        Loading detection results...
      </div>
    );
  }

  if (error && detections.length === 0) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--danger)' }}>
        Failed to fetch detections: {error}
      </div>
    );
  }

  if (detections.length === 0) {
    return <EmptyState title="No detections recorded" message="AI and signature detector engines have not flagged anomalies yet." />;
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
            <th style={{ padding: '0.75rem 1rem' }}>Detection ID</th>
            <th style={{ padding: '0.75rem 1rem' }}>Engine / Model</th>
            <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
            <th style={{ padding: '0.75rem 1rem' }}>Confidence</th>
            <th style={{ padding: '0.75rem 1rem' }}>Source Flow</th>
            <th style={{ padding: '0.75rem 1rem' }}>MITRE Technique</th>
            <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {detections.map((d) => (
            <tr
              key={d.detection_id}
              style={{
                borderBottom: '1px solid var(--border)',
                transition: 'background 0.15s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                {d.detection_id.slice(0, 8)}...
              </td>
              <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>
                {(d as any).detector_name || d.detector_type}
              </td>
              <td style={{ padding: '0.75rem 1rem' }}>
                <Badge variant={typeof d.severity === 'string' ? d.severity.toLowerCase() : 'info'}>
                  {d.severity}
                </Badge>
              </td>
              <td style={{ padding: '0.75rem 1rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--accent)' }}>
                  {(d.confidence * 100).toFixed(1)}%
                </span>
              </td>
              <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                {d.flow_id.slice(0, 10)}...
              </td>
              <td style={{ padding: '0.75rem 1rem' }}>
                {(d as any).mitre_technique ? (
                  <code style={{ color: 'var(--primary-glow)', background: 'rgba(99, 102, 241, 0.1)', padding: '0.1rem 0.3rem', borderRadius: '3px' }}>
                    {(d as any).mitre_technique}
                  </code>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>-</span>
                )}
              </td>
              <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                {new Date(d.detection_timestamp || (d as any).created_at || new Date()).toLocaleTimeString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

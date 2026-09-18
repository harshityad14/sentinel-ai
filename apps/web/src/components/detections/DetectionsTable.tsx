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
      <table className="soc-table">
        <thead>
          <tr>
            <th>Detection ID</th>
            <th>Engine / Model</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Source Flow</th>
            <th>MITRE Technique</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {detections.map((d) => (
            <tr key={d.detection_id}>
              <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {d.detection_id.slice(0, 8)}...
              </td>
              <td style={{ fontWeight: 600, color: '#0f172a' }}>
                {(d as any).detector_name || d.detector_type}
              </td>
              <td>
                <Badge variant={typeof d.severity === 'string' ? d.severity.toLowerCase() : 'info'}>
                  {d.severity}
                </Badge>
              </td>
              <td>
                <span style={{ fontWeight: 600, color: '#1d4ed8', fontFamily: 'var(--font-mono)' }}>
                  {(d.confidence * 100).toFixed(1)}%
                </span>
              </td>
              <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {d.flow_id ? `${d.flow_id.slice(0, 10)}...` : '-'}
              </td>
              <td>
                {(d as any).mitre_technique ? (
                  <code style={{ color: '#1d4ed8', background: '#eff6ff', border: '1px solid #bfdbfe', padding: '0.1rem 0.35rem', borderRadius: '3px', fontSize: '0.75rem' }}>
                    {(d as any).mitre_technique}
                  </code>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>-</span>
                )}
              </td>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {new Date(d.detection_timestamp || (d as any).created_at || new Date()).toLocaleTimeString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

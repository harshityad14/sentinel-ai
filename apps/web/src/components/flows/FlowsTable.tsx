import React from 'react';
import type { FlowRecordRead } from '../../types/flow';
import { EmptyState } from '../common/EmptyState';

interface FlowsTableProps {
  flows: FlowRecordRead[];
  loading: boolean;
  error: string | null;
}

export const FlowsTable: React.FC<FlowsTableProps> = ({ flows, loading, error }) => {
  if (loading && flows.length === 0) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
        Loading captured network flows...
      </div>
    );
  }

  if (error && flows.length === 0) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--danger)' }}>
        Failed to fetch flows: {error}
      </div>
    );
  }

  if (flows.length === 0) {
    return <EmptyState title="No flow records observed" message="Passive flow ingestion has not captured flows in the selected window." />;
  }

  const getProtocolName = (proto: string | number) => {
    if (proto === 6 || proto === 'TCP') return 'TCP';
    if (proto === 17 || proto === 'UDP') return 'UDP';
    if (proto === 1 || proto === 'ICMP') return 'ICMP';
    return String(proto);
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
            <th style={{ padding: '0.75rem 1rem' }}>Flow ID</th>
            <th style={{ padding: '0.75rem 1rem' }}>Protocol</th>
            <th style={{ padding: '0.75rem 1rem' }}>Source</th>
            <th style={{ padding: '0.75rem 1rem' }}>Destination</th>
            <th style={{ padding: '0.75rem 1rem' }}>Packets</th>
            <th style={{ padding: '0.75rem 1rem' }}>Bytes</th>
            <th style={{ padding: '0.75rem 1rem' }}>Duration</th>
            <th style={{ padding: '0.75rem 1rem' }}>TCP Flags</th>
            <th style={{ padding: '0.75rem 1rem' }}>End Time</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((flow) => {
            const protoStr = getProtocolName(flow.protocol);
            const pkts = (flow as any).packet_count ?? flow.total_packets ?? 0;
            const bytes = (flow as any).byte_count ?? flow.total_bytes ?? 0;
            const duration = (flow as any).duration_seconds ?? flow.duration_sec ?? 0;
            const endTime = flow.end_time || flow.last_seen_time || flow.start_time || new Date().toISOString();
            const flagsStr =
              typeof flow.tcp_flags === 'object' && flow.tcp_flags !== null
                ? Object.keys(flow.tcp_flags).join(',')
                : flow.tcp_flags || '-';

            return (
              <tr
                key={flow.flow_id}
                style={{
                  borderBottom: '1px solid var(--border)',
                  transition: 'background 0.15s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                  {flow.flow_id.slice(0, 8)}...
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <span
                    style={{
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      background: protoStr === 'TCP' ? 'rgba(59, 130, 246, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      color: protoStr === 'TCP' ? '#60a5fa' : '#34d399',
                    }}
                  >
                    {protoStr}
                  </span>
                </td>
                <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>
                  {flow.source_ip}:{flow.source_port}
                </td>
                <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>
                  {flow.destination_ip}:{flow.destination_port}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  {pkts.toLocaleString()}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  {bytes > 1024 * 1024
                    ? `${(bytes / (1024 * 1024)).toFixed(1)} MB`
                    : `${(bytes / 1024).toFixed(1)} KB`}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  {duration.toFixed(2)}s
                </td>
                <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                  {flagsStr}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  {new Date(endTime).toLocaleTimeString()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

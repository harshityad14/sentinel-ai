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
      <table className="soc-table">
        <thead>
          <tr>
            <th>Flow ID</th>
            <th>Protocol</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Duration</th>
            <th>TCP Flags</th>
            <th>End Time</th>
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
              <tr key={flow.flow_id}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  {flow.flow_id.slice(0, 8)}...
                </td>
                <td>
                  <span
                    style={{
                      padding: '0.15rem 0.45rem',
                      borderRadius: '4px',
                      fontSize: '0.725rem',
                      fontWeight: 600,
                      background: protoStr === 'TCP' ? '#eff6ff' : '#f0fdf4',
                      color: protoStr === 'TCP' ? '#1d4ed8' : '#16a34a',
                      border: protoStr === 'TCP' ? '1px solid #bfdbfe' : '1px solid #bbf7d0',
                    }}
                  >
                    {protoStr}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: '#0f172a' }}>
                  {flow.source_ip}:{flow.source_port}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: '#0f172a' }}>
                  {flow.destination_ip}:{flow.destination_port}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>
                  {pkts.toLocaleString()}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>
                  {bytes > 1024 * 1024
                    ? `${(bytes / (1024 * 1024)).toFixed(1)} MB`
                    : `${(bytes / 1024).toFixed(1)} KB`}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>
                  {duration.toFixed(2)}s
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  {flagsStr}
                </td>
                <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
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

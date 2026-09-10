import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AlertsTable } from '../components/alerts/AlertsTable';
import { AlertFilters } from '../components/alerts/AlertFilters';
import { EvidenceViewer } from '../components/alerts/EvidenceViewer';
import type { SecurityAlertRead } from '../types/alert';

const mockAlert: SecurityAlertRead = {
  alert_id: 'alt-12345678-abcd',
  threat_class: 'SYN_FLOOD',
  title: 'SYN Flood Detected',
  severity: 'CRITICAL',
  status: 'NEW',
  confidence: 0.98,
  risk_score: 92.4,
  flow_ids: ['flw-001'],
  first_seen: '2026-09-10T12:00:00Z',
  last_seen: '2026-09-10T12:00:00Z',
  source_ip: '192.168.1.100',
  destination_ip: '10.0.0.5',
  explanation: 'High volume of SYN packets observed without completing 3-way handshakes.',
  mitre_tactics: ['TA0040'],
  detection_signals: [
    {
      signal_id: 'sig-001',
      flow_id: 'flw-001',
      threat_type: 'DOS_SYN_FLOOD',
      detector_type: 'syn_flood_detector',
      detector_name: 'syn_flood_detector',
      severity: 'CRITICAL',
      confidence: 0.98,
      timestamp: '2026-09-10T12:00:00Z',
    },
  ],
  evidence: {
    syn_count: 5400,
    syn_ack_ratio: 0.002,
  } as any,
  created_at: '2026-09-10T12:00:00Z',
  updated_at: '2026-09-10T12:00:00Z',
};

describe('Alerts Table & Components', () => {
  it('renders alerts table rows with title and severity', () => {
    const handleSelect = vi.fn();
    render(
      <AlertsTable
        alerts={[mockAlert]}
        total={1}
        limit={50}
        offset={0}
        onSort={vi.fn()}
        onPageChange={vi.fn()}
        onSelectAlert={handleSelect}
        loading={false}
        error={null}
      />
    );

    expect(screen.getByText('SYN Flood Detected')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.100')).toBeInTheDocument();

    fireEvent.click(screen.getByText('SYN Flood Detected'));
    expect(handleSelect).toHaveBeenCalledWith(mockAlert);
  });

  it('renders evidence viewer key-value pairs', () => {
    render(<EvidenceViewer evidence={mockAlert.evidence} />);
    expect(screen.getByText(/syn_count/)).toBeInTheDocument();
    expect(screen.getByText('5400')).toBeInTheDocument();
    expect(screen.getByText(/syn_ack_ratio/)).toBeInTheDocument();
  });

  it('handles alert filters change', () => {
    const handleFilterChange = vi.fn();
    const handleReset = vi.fn();

    render(
      <AlertFilters
        filters={{ limit: 50, offset: 0 }}
        onFilterChange={handleFilterChange}
        onReset={handleReset}
      />
    );

    const severitySelect = screen.getByLabelText('Filter by severity');
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } });

    expect(handleFilterChange).toHaveBeenCalledWith(expect.objectContaining({ severity: 'CRITICAL' }));
  });
});

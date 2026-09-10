import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from '../components/common/Badge';
import { StatusPill } from '../components/common/StatusPill';
import { RiskGauge } from '../components/common/RiskGauge';
import { ConnectionIndicator } from '../components/common/ConnectionIndicator';

describe('Common UI Components', () => {
  it('renders severity badges correctly', () => {
    render(<Badge variant="critical">CRITICAL</Badge>);
    const badge = screen.getByText('CRITICAL');
    expect(badge).toBeInTheDocument();
  });

  it('renders status pills with correct label', () => {
    render(<StatusPill status="NEW" />);
    expect(screen.getByText('NEW')).toBeInTheDocument();
  });

  it('renders risk score in RiskGauge', () => {
    render(<RiskGauge score={85.5} />);
    expect(screen.getByText('86')).toBeInTheDocument();
  });

  it('renders connection indicator status', () => {
    render(<ConnectionIndicator status="CONNECTED" reconnectCount={0} />);
    expect(screen.getByText('LIVE STREAM')).toBeInTheDocument();

    render(<ConnectionIndicator status="POLLING_FALLBACK" reconnectCount={6} />);
    expect(screen.getByText('POLLING (WS OFFLINE)')).toBeInTheDocument();
  });
});

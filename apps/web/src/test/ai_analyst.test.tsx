import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AIAnalystPanel } from '../components/ai/AIAnalystPanel';
import * as aiApi from '../api/ai_analyst';
import type { AlertAnalysisReport, AnalystQuestionResponse } from '../types/ai_analyst';
import type { SecurityAlertRead } from '../types/alert';

const mockAlert: SecurityAlertRead = {
  alert_id: 'alt-ai-test-1',
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
  signals: [],
  evidence_items: [],
  entities: [],
  lifecycle_history: [],
  created_at: '2026-09-10T12:00:00Z',
  updated_at: '2026-09-10T12:00:00Z',
  risk_level: 'CRITICAL',
};

const mockReport: AlertAnalysisReport = {
  analysis_id: 'rep-001',
  alert_id: 'alt-ai-test-1',
  generated_at: '2026-09-10T12:01:00Z',
  model_identifier: 'mock-analyst-v1',
  executive_summary: 'Critical SYN flood targeting internal gateway 10.0.0.5 from 192.168.1.100.',
  observed_facts: ['Observed 5,400 SYN packets in 10-second window.'],
  threat_assessment: 'Volumetric state exhaustion attack.',
  threat_reasoning: 'Missing ACK responses indicate automated attack script.',
  risk_interpretation: 'Risk score 92 driven by detector consensus.',
  evidence_citations: [
    {
      citation_id: 'EVID-01',
      detector_name: 'syn_detector',
      feature_name: 'syn_ratio',
      observed_value: 0.98,
      threshold_value: 0.85,
      relevance: 'SYN ratio exceeded configured threshold',
    },
  ],
  attack_stage: {
    stage_name: 'Impact',
    kill_chain_phase: 'Impact',
    confidence: 0.95,
    supporting_evidence_ids: ['EVID-01'],
  },
  mitre_explanation: 'Maps to Network Denial of Service (T1498).',
  false_positive_analysis: 'Unlikely to be legitimate traffic.',
  recommended_investigation_steps: [
    {
      step_number: 1,
      priority: 'HIGH',
      action: 'Check edge router traffic metrics to confirm upstream volume',
      target_entity: '10.0.0.5',
      rationale: 'Confirm packet volume alignment',
    },
  ],
  uncertainties: [
    {
      aspect: 'Source spoofing',
      reason: 'Single source IP observed without reverse-path verification',
      recommended_telemetry: 'Upstream router NetFlow interface statistics',
    },
  ],
  is_fallback: false,
  fallback_reason: null,
  cache_hit: false,
  validation_log: {
    total_entities_checked: 3,
    verified_entities_count: 3,
    unsupported_entities: [],
    validation_status: 'PASSED',
  },
};

describe('AIAnalystPanel Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders initial prompt and button when no analysis is cached', async () => {
    vi.spyOn(aiApi, 'getCachedAlertAnalysis').mockRejectedValue(new Error('Not found'));

    render(<AIAnalystPanel alertId={mockAlert.alert_id} alert={mockAlert} />);

    expect(screen.getByText('GenAI Security Analyst Copilot')).toBeInTheDocument();
    expect(screen.getByText('Analyze Alert')).toBeInTheDocument();
  });

  it('triggers analysis on button click and renders report content', async () => {
    vi.spyOn(aiApi, 'getCachedAlertAnalysis').mockRejectedValue(new Error('Not found'));
    vi.spyOn(aiApi, 'fetchAlertAnalysis').mockResolvedValue(mockReport);

    render(<AIAnalystPanel alertId={mockAlert.alert_id} alert={mockAlert} />);

    const analyzeBtn = screen.getByText('Analyze Alert');
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(screen.getByText(/Critical SYN flood targeting internal gateway/i)).toBeInTheDocument();
      expect(screen.getByText(/Stage: Impact/i)).toBeInTheDocument();
      expect(screen.getByText(/EVID-01/i)).toBeInTheDocument();
      expect(screen.getByText(/Check edge router traffic metrics/i)).toBeInTheDocument();
    });
  });

  it('displays amber warning banner when report was generated via fallback', async () => {
    const fallbackReport: AlertAnalysisReport = {
      ...mockReport,
      is_fallback: true,
      fallback_reason: 'Remote LLM provider offline',
    };
    vi.spyOn(aiApi, 'getCachedAlertAnalysis').mockResolvedValue(fallbackReport);

    render(<AIAnalystPanel alertId={mockAlert.alert_id} alert={mockAlert} />);

    await waitFor(() => {
      expect(screen.getByText(/Local Heuristic Synthesis:/i)).toBeInTheDocument();
      expect(screen.getByText(/Remote LLM provider offline/i)).toBeInTheDocument();
    });
  });

  it('submits analyst question and renders assistant answer with citations', async () => {
    vi.spyOn(aiApi, 'getCachedAlertAnalysis').mockResolvedValue(mockReport);
    const mockQaResp: AnalystQuestionResponse = {
      alert_id: mockAlert.alert_id,
      question: 'What was the SYN ratio?',
      answer: 'The observed SYN ratio was 0.98, breaching the threshold.',
      evidence_citations: [
        {
          citation_id: 'EVID-01',
          detector_name: 'syn_detector',
          feature_name: 'syn_ratio',
          observed_value: 0.98,
          relevance: 'Primary metric',
        },
      ],
      grounded_in_telemetry: true,
      cache_hit: false,
    };
    vi.spyOn(aiApi, 'askAnalystQuestion').mockResolvedValue(mockQaResp);

    render(<AIAnalystPanel alertId={mockAlert.alert_id} alert={mockAlert} />);

    await waitFor(() => {
      expect(screen.getByText('Interactive Analyst Q&A')).toBeInTheDocument();
    });

    const input = screen.getByPlaceholderText(/Ask a question about this incident/i);
    fireEvent.change(input, { target: { value: 'What was the SYN ratio?' } });

    const sendBtn = screen.getByRole('button', { name: 'Send' });
    fireEvent.click(sendBtn);

    await waitFor(() => {
      expect(screen.getByText('The observed SYN ratio was 0.98, breaching the threshold.')).toBeInTheDocument();
    });
  });
});

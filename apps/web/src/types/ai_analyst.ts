export interface EvidenceCitation {
  citation_id: string;
  detector_name: string;
  feature_name?: string | null;
  observed_value: any;
  threshold_value?: any | null;
  relevance: string;
}

export interface AttackStageAnalysis {
  stage_name: string;
  kill_chain_phase: string;
  confidence: number;
  supporting_evidence_ids: string[];
}

export interface InvestigationStep {
  step_number: number;
  priority: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  action: string;
  target_entity: string;
  rationale: string;
}

export interface UncertaintyIndicator {
  aspect: string;
  reason: string;
  recommended_telemetry?: string | null;
}

export interface AuditableValidationLog {
  total_entities_checked: number;
  verified_entities_count: number;
  unsupported_entities: string[];
  validation_status: 'PASSED' | 'FLAGGED_UNGROUNDED' | string;
}

export interface AlertAnalysisReport {
  analysis_id: string;
  alert_id: string;
  generated_at: string;
  model_identifier: string;
  executive_summary: string;
  observed_facts: string[];
  threat_assessment: string;
  threat_reasoning: string;
  risk_interpretation: string;
  evidence_citations: EvidenceCitation[];
  attack_stage: AttackStageAnalysis;
  mitre_explanation: string;
  false_positive_analysis: string;
  recommended_investigation_steps: InvestigationStep[];
  uncertainties: UncertaintyIndicator[];
  is_fallback: boolean;
  fallback_reason?: string | null;
  cache_hit: boolean;
  validation_log: AuditableValidationLog;
}

export interface AnalystQuestionRequest {
  question: string;
  conversation_history?: Array<{ role: string; content: string }>;
}

export interface AnalystQuestionResponse {
  alert_id: string;
  question: string;
  answer: string;
  evidence_citations: EvidenceCitation[];
  grounded_in_telemetry: boolean;
  uncertainty_notes?: string | null;
  cache_hit: boolean;
}

export interface AIHealthResponse {
  status: string;
  provider: Record<string, any>;
  cache: Record<string, any>;
  metrics: Record<string, any>;
  config: Record<string, any>;
}

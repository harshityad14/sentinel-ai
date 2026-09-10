/**
 * Domain types for Security Alerts matching Phase 4 & Phase 5 Pydantic models.
 */

export type AlertSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AlertStatus = "NEW" | "ACTIVE" | "ACKNOWLEDGED" | "RESOLVED";

export type ThreatClass =
  | "SYN_FLOOD"
  | "PORT_SCAN"
  | "DNS_TUNNELING"
  | "DNS_DGA"
  | "C2_BEACONING"
  | "DATA_EXFILTRATION"
  | "SUSPICIOUS_TLS"
  | "BEHAVIORAL_ANOMALY"
  | "UNKNOWN";

export interface RiskScoreBreakdown {
  base?: number;
  confidence?: number;
  severity?: number;
  agreement?: number;
  recurrence?: number;
  temporal?: number;
  [key: string]: number | undefined;
}

export interface RiskScoreRead {
  score: number;
  level?: string;
  confidence_factor?: number;
  severity_factor?: number;
  agreement_factor?: number;
  signal_count_factor?: number;
  recurrence_factor?: number;
  temporal_proximity_factor?: number;
  breakdown?: RiskScoreBreakdown;
  explanation?: string;
}

export interface AlertEvidenceRead {
  evidence_id?: string;
  detector_name: string;
  evidence_type?: string;
  description?: string;
  raw_values?: Record<string, any>;
  raw_indicators?: Record<string, any>;
  triggered_features?: Record<string, any>;
  confidence?: number;
  confidence_contribution?: number;
  weight?: number;
}

export interface AlertSignalRead {
  signal_id: string;
  detection_id?: string;
  flow_id: string;
  threat_type: string;
  detector_type: string;
  detector_name?: string;
  severity: AlertSeverity | string;
  confidence: number;
  timestamp: string;
  description?: string;
}

export interface AlertEntityRead {
  entity_id?: string;
  entity_type: "IP" | "HOST" | "SUBNET" | "ENDPOINT" | string;
  identifier: string;
  role?: string;
  confidence?: number;
}

export interface MitreAttackRefRead {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  subtechnique_id?: string;
}

export interface LifecycleHistoryRead {
  history_id?: string;
  previous_status: string;
  new_status: AlertStatus;
  changed_at: string;
  changed_by: string;
  notes?: string;
}

export interface SecurityAlertRead {
  alert_id: string;
  correlation_group_id?: string;
  threat_class: ThreatClass | string;
  severity: AlertSeverity;
  status: AlertStatus;
  confidence: number;
  risk_score: number | RiskScoreRead;
  risk_level?: AlertSeverity | string;
  risk_breakdown?: RiskScoreBreakdown;
  title: string;
  description?: string;
  explanation: string;
  flow_ids: string[];
  source_ip?: string;
  destination_ip?: string;
  first_seen: string;
  last_seen: string;
  created_at?: string;
  updated_at?: string;
  signals?: AlertSignalRead[];
  contributing_signals?: AlertSignalRead[];
  evidence_items?: AlertEvidenceRead[];
  evidence?: AlertEvidenceRead[];
  entities?: AlertEntityRead[];
  mitre_attack?: MitreAttackRefRead[];
  mitre_tactics?: string[];
  detection_signals?: AlertSignalRead[];
  correlation_id?: string;
  assigned_to?: string;
  comments?: Array<{ author: string; timestamp?: string; text: string }>;
}

export type DetectionSignal = AlertSignalRead;
export type SecurityAlertStats = AlertStatisticsRead;

export interface AlertStatisticsRead {
  total_alerts: number;
  unresolved_alerts?: number;
  avg_risk_score?: number;
  by_status: Record<AlertStatus | string, number>;
  by_severity: Record<AlertSeverity | string, number>;
  by_threat_class: Record<string, number>;
  active_correlation_groups: number;
  mean_risk_score: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface AlertFilterParams {
  threat_class?: string;
  severity?: string;
  status?: string;
  min_confidence?: number;
  max_confidence?: number;
  min_risk?: number;
  max_risk?: number;
  start_time?: string;
  end_time?: string;
  search?: string;
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_desc?: boolean;
}

/**
 * Domain types for Detection results matching Phase 3 & Phase 5 models.
 */

export interface DetectionResultRead {
  detection_id: string;
  flow_id: string;
  threat_type: string;
  detector_type: string;
  confidence: number;
  severity: string;
  detection_timestamp: string;
  explanation: string;
  context?: Record<string, any>;
  signals?: any[];
  evidence?: any[];
}

export interface DetectionFilterParams {
  threat_type?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}

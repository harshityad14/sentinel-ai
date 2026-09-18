import { request } from "./client";

export interface SystemHealth {
  status: string;
  service?: string;
  app?: string;
  version: string;
  environment?: string;
  timestamp?: string;
}

export interface SystemReadiness {
  status: string;
  database: boolean;
  environment: string;
  version: string;
}

export interface ProcessingStatus {
  pipeline_status: string;
  passive_mode_active: boolean;
  total_flows_processed: number;
  total_detections_generated: number;
  total_alerts_persisted: number;
}

export interface ThreatDistributionItem {
  threat_type: string;
  count: number;
}

export interface EntityStatisticsItem {
  identifier: string;
  entity_type: string;
  alert_count: number;
}

export interface TelemetrySummary {
  total_flows: number;
  total_detections: number;
  total_alerts: number;
  threat_distribution: ThreatDistributionItem[];
  top_entities: EntityStatisticsItem[];
}

export interface PlatformStatistics {
  database_status: string;
  total_flows: number;
  total_detections: number;
  total_alerts: number;
  timestamp: string;
}

export async function fetchHealth(): Promise<SystemHealth> {
  return request<SystemHealth>("/health");
}

export async function fetchReadiness(): Promise<SystemReadiness> {
  return request<SystemReadiness>("/readiness");
}

export async function fetchProcessingStatus(): Promise<ProcessingStatus> {
  return request<ProcessingStatus>("/status");
}

export async function fetchTelemetrySummary(): Promise<TelemetrySummary> {
  return request<TelemetrySummary>("/statistics/summary");
}

export async function fetchThreatDistribution(): Promise<ThreatDistributionItem[]> {
  return request<ThreatDistributionItem[]>("/statistics/threats");
}

export async function fetchEntityStatistics(limit: number = 20): Promise<EntityStatisticsItem[]> {
  return request<EntityStatisticsItem[]>(`/statistics/entities?limit=${limit}`);
}

export async function fetchPlatformStatistics(): Promise<PlatformStatistics> {
  return request<PlatformStatistics>("/statistics");
}

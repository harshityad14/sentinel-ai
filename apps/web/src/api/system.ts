import { request } from "./client";

export interface SystemHealth {
  status: string;
  app: string;
  version: string;
  environment: string;
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

export async function fetchPlatformStatistics(): Promise<PlatformStatistics> {
  return request<PlatformStatistics>("/statistics");
}

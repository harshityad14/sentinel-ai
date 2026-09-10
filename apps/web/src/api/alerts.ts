import { request } from "./client";
import {
  AlertFilterParams,
  AlertStatisticsRead,
  PaginatedResponse,
  SecurityAlertRead,
} from "../types/alert";

export async function fetchAlerts(
  params: AlertFilterParams = {}
): Promise<PaginatedResponse<SecurityAlertRead>> {
  const query = new URLSearchParams();

  if (params.threat_class) query.append("threat_class", params.threat_class);
  if (params.severity) query.append("severity", params.severity);
  if (params.status) query.append("status", params.status);
  if (params.min_confidence !== undefined)
    query.append("min_confidence", params.min_confidence.toString());
  if (params.max_confidence !== undefined)
    query.append("max_confidence", params.max_confidence.toString());
  if (params.min_risk !== undefined)
    query.append("min_risk", params.min_risk.toString());
  if (params.max_risk !== undefined)
    query.append("max_risk", params.max_risk.toString());
  if (params.start_time) query.append("start_time", params.start_time);
  if (params.end_time) query.append("end_time", params.end_time);
  if (params.limit !== undefined) query.append("limit", params.limit.toString());
  if (params.offset !== undefined) query.append("offset", params.offset.toString());
  if (params.sort_by) query.append("sort_by", params.sort_by);
  if (params.sort_desc !== undefined)
    query.append("sort_desc", params.sort_desc.toString());

  const queryString = query.toString();
  const endpoint = `/alerts${queryString ? `?${queryString}` : ""}`;
  return request<PaginatedResponse<SecurityAlertRead>>(endpoint);
}

export async function fetchAlertById(alertId: string): Promise<SecurityAlertRead> {
  return request<SecurityAlertRead>(`/alerts/${encodeURIComponent(alertId)}`);
}

export async function fetchAlertStatistics(): Promise<AlertStatisticsRead> {
  return request<AlertStatisticsRead>("/alerts/statistics");
}

export async function acknowledgeAlert(
  alertId: string,
  changedBy: string = "analyst-1",
  notes: string = "Alert claimed by operator"
): Promise<SecurityAlertRead> {
  return request<SecurityAlertRead>(
    `/alerts/${encodeURIComponent(alertId)}/acknowledge`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ changed_by: changedBy, notes }),
    }
  );
}

export async function resolveAlert(
  alertId: string,
  changedBy: string = "analyst-1",
  notes: string = "Incident investigation completed"
): Promise<SecurityAlertRead> {
  return request<SecurityAlertRead>(
    `/alerts/${encodeURIComponent(alertId)}/resolve`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ changed_by: changedBy, notes }),
    }
  );
}export async function updateAlertLifecycle(
  alertId: string,
  newStatus: string,
  changedBy: string = "analyst-1",
  notes: string = ""
): Promise<SecurityAlertRead> {
  if (newStatus === "RESOLVED") {
    return resolveAlert(alertId, changedBy, notes);
  }
  return acknowledgeAlert(alertId, changedBy, notes);
}

export const getAlerts = fetchAlerts;
export const getAlertStats = fetchAlertStatistics;
export const getAlertById = fetchAlertById;


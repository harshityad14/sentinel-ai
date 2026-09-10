import { request } from "./client";
import { DetectionResultRead } from "../types/detection";
import { PaginatedResponse } from "../types/alert";

export async function fetchDetections(
  params: { threat_type?: string; severity?: string; limit?: number; offset?: number } = {}
): Promise<PaginatedResponse<DetectionResultRead>> {
  const query = new URLSearchParams();
  if (params.threat_type) query.append("threat_type", params.threat_type);
  if (params.severity) query.append("severity", params.severity);
  if (params.limit !== undefined) query.append("limit", params.limit.toString());
  if (params.offset !== undefined) query.append("offset", params.offset.toString());

  const queryString = query.toString();
  return request<PaginatedResponse<DetectionResultRead>>(
    `/detections${queryString ? `?${queryString}` : ""}`
  );
}

export async function fetchDetectionById(detectionId: string): Promise<DetectionResultRead> {
  return request<DetectionResultRead>(`/detections/${encodeURIComponent(detectionId)}`);
}export const getDetections = fetchDetections;

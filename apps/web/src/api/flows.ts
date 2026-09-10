import { request } from "./client";
import { FlowFilterParams, FlowRecordRead } from "../types/flow";
import { PaginatedResponse } from "../types/alert";

export async function fetchFlows(
  params: FlowFilterParams = {}
): Promise<PaginatedResponse<FlowRecordRead>> {
  const query = new URLSearchParams();
  if (params.src_ip) query.append("src_ip", params.src_ip);
  if (params.dst_ip) query.append("dst_ip", params.dst_ip);
  if (params.protocol) query.append("protocol", params.protocol);
  if (params.min_bytes !== undefined) query.append("min_bytes", params.min_bytes.toString());
  if (params.max_bytes !== undefined) query.append("max_bytes", params.max_bytes.toString());
  if (params.limit !== undefined) query.append("limit", params.limit.toString());
  if (params.offset !== undefined) query.append("offset", params.offset.toString());

  const queryString = query.toString();
  return request<PaginatedResponse<FlowRecordRead>>(`/flows${queryString ? `?${queryString}` : ""}`);
}

export async function fetchFlowById(flowId: string): Promise<FlowRecordRead> {
  return request<FlowRecordRead>(`/flows/${encodeURIComponent(flowId)}`);
}export const getFlows = fetchFlows;

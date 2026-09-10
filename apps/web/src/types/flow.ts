/**
 * Domain types for Network Flow records matching FlowRecord models.
 */

export type ProtocolType = "TCP" | "UDP" | "ICMP" | "OTHER";

export interface FlowRecordRead {
  flow_id: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: ProtocolType;
  total_packets: number;
  forward_packets?: number;
  backward_packets?: number;
  total_bytes: number;
  forward_bytes?: number;
  backward_bytes?: number;
  duration_sec: number;
  start_time: string;
  last_seen_time?: string;
  end_time?: string;
  tcp_flags?: Record<string, number>;
  termination_reason?: string;
  is_active?: boolean;
}

export interface FlowFilterParams {
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  min_bytes?: number;
  max_bytes?: number;
  limit?: number;
  offset?: number;
}

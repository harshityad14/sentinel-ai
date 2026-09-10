"""Phase 2 Feature Extraction performance benchmark utility.

Measures:
- flows processed
- feature extraction time (seconds)
- flows/sec (extraction throughput)
"""

import argparse
from datetime import datetime, timezone
import time
from typing import List, Tuple

from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_models.events import DNSMetadata, FlowRecord, ProtocolType, TLSMetadata


def create_synthetic_flow_records(num_flows: int = 10000) -> List[FlowRecord]:
    """Generate a batch of diverse synthetic FlowRecords for benchmarking."""
    flows = []
    now = datetime.now(timezone.utc)

    for i in range(num_flows):
        is_tcp = (i % 2 == 0)
        has_dns = (i % 3 == 0)
        has_tls = is_tcp and (i % 4 == 0)

        flags = {"syn": 2, "ack": 10, "fin": 1, "rst": 0, "psh": 4, "urg": 0, "ece": 0, "cwr": 0} if is_tcp else {}
        dns_ctx = DNSMetadata(query_name=f"subdomain-{i}.example.corp", query_type="A", response_code="NOERROR") if has_dns else None
        tls_ctx = TLSMetadata(sni="api.example.corp", version="TLS 1.3", ja3="771,4865,43-51,29,0") if has_tls else None

        flow = FlowRecord(
            flow_id=f"benchmark_flow_{i}",
            start_time=now,
            end_time=now,
            duration_sec=12.5,
            source_ip=f"192.168.1.{i % 250 + 1}",
            destination_ip="10.0.0.1",
            source_port=10000 + (i % 50000),
            destination_port=443 if is_tcp else 53,
            protocol=ProtocolType.TCP if is_tcp else ProtocolType.UDP,
            total_packets=30,
            forward_packets=18,
            backward_packets=12,
            total_bytes=15000,
            forward_bytes=9000,
            backward_bytes=6000,
            min_packet_size=64,
            max_packet_size=1500,
            mean_packet_size=500.0,
            std_packet_size=200.0,
            tcp_flags=flags,
            dns_context=dns_ctx,
            tls_context=tls_ctx,
        )
        flows.append(flow)

    return flows


def run_feature_benchmark(num_flows: int = 10000) -> Tuple[int, float, float]:
    """Execute feature extraction benchmark."""
    flows = create_synthetic_flow_records(num_flows)
    extractor = UnifiedFeatureExtractor()

    start_time = time.perf_counter()
    for flow in flows:
        _ = extractor.extract(flow)
    elapsed = max(1e-6, time.perf_counter() - start_time)
    fps = num_flows / elapsed

    return num_flows, elapsed, fps


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Phase 2 Feature Extraction Baseline Benchmark")
    parser.add_argument("-f", "--flows", type=int, default=10000, help="Number of flows to extract (default: 10000)")
    args = parser.parse_args()

    print(f"\n=======================================================")
    print(f" SentinelAI Phase 2 Feature Extraction Benchmark")
    print(f" Workload: {args.flows:,} synthetic FlowRecord objects")
    print(f"=======================================================")
    print("Extracting feature vectors...")

    flows_count, elapsed, fps = run_feature_benchmark(num_flows=args.flows)

    print(f"\nResults:")
    print(f"  - Flows Processed:          {flows_count:,}")
    print(f"  - Extraction Time:          {elapsed:.4f} seconds")
    print(f"  - Feature Extraction Rate:  {fps:,.1f} flows/sec")
    print(f"  - Avg Latency Per Flow:     {(elapsed / flows_count) * 1_000_000:.2f} microseconds/flow")
    print(f"=======================================================\n")


if __name__ == "__main__":
    main()

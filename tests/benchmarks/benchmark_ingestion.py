"""Phase 1 performance baseline measurement utility.

Measures:
- packets processed
- flows generated
- processing time (seconds)
- packets/sec (throughput)
- flows/sec (throughput)
"""

import argparse
import tempfile
import time
from pathlib import Path
from typing import Tuple

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from sentinel_flow_engine.aggregator import BidirectionalFlowAggregator
from sentinel_ingestion.pcap_source import PcapPacketSource

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"


def generate_benchmark_pcap(path: Path, num_packets: int = 10000, num_flows: int = 500) -> None:
    """Generate a synthetic PCAP with num_packets distributed across num_flows."""
    packets = []
    base_time = 1700000000.0

    for i in range(num_packets):
        flow_idx = i % num_flows
        client_port = 10000 + flow_idx
        server_port = 80 if (flow_idx % 2 == 0) else 443

        is_fwd = (i // num_flows) % 2 == 0
        if is_fwd:
            pkt = Ether(src=ETH_SRC, dst=ETH_DST) / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=client_port, dport=server_port, flags="PA") / (b"X" * 64)
        else:
            pkt = Ether(src=ETH_DST, dst=ETH_SRC) / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=server_port, dport=client_port, flags="A") / (b"Y" * 128)

        pkt.time = base_time + (i * 0.001)
        packets.append(pkt)

    wrpcap(str(path), packets)


def run_benchmark(num_packets: int = 10000, num_flows: int = 500) -> Tuple[int, int, float, float, float]:
    """Execute the benchmark and return metrics."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_pcap = Path(tmp.name)

    try:
        generate_benchmark_pcap(tmp_pcap, num_packets=num_packets, num_flows=num_flows)
        
        aggregator = BidirectionalFlowAggregator(inactivity_timeout_sec=30.0)
        packet_count = 0
        flow_count = 0

        start_time = time.perf_counter()
        
        with PcapPacketSource(tmp_pcap) as source:
            for pkt in source.stream_packets():
                packet_count += 1
                terminated = aggregator.add_packet(pkt)
                if terminated is not None:
                    flow_count += 1
                for expired in aggregator.flush_expired(pkt.timestamp):
                    flow_count += 1

            for remaining in aggregator.flush_all():
                flow_count += 1

        elapsed = max(1e-6, time.perf_counter() - start_time)
        pps = packet_count / elapsed
        fps = flow_count / elapsed

        return packet_count, flow_count, elapsed, pps, fps

    finally:
        if tmp_pcap.exists():
            tmp_pcap.unlink()


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Phase 1 Ingestion & Flow Engine Baseline Benchmark")
    parser.add_argument("-n", "--packets", type=int, default=5000, help="Number of packets in synthetic benchmark (default: 5000)")
    parser.add_argument("-f", "--flows", type=int, default=250, help="Number of concurrent flows (default: 250)")
    args = parser.parse_args()

    print(f"\n=======================================================")
    print(f" SentinelAI Phase 1 Performance Baseline Benchmark")
    print(f" Workload: {args.packets} packets across {args.flows} bidirectional flows")
    print(f"=======================================================")
    print("Generating synthetic benchmark trace and executing pipeline...")

    pkts, flows, elapsed, pps, fps = run_benchmark(num_packets=args.packets, num_flows=args.flows)

    print(f"\nResults:")
    print(f"  - Packets Processed:        {pkts:,}")
    print(f"  - Bidirectional Flows:      {flows:,}")
    print(f"  - Execution Time:           {elapsed:.4f} seconds")
    print(f"  - Ingestion Throughput:     {pps:,.1f} packets/sec")
    print(f"  - Flow Processing Rate:     {fps:,.1f} flows/sec")
    print(f"=======================================================\n")


if __name__ == "__main__":
    main()

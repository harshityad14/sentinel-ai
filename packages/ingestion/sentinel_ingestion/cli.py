"""Command Line Interface for passive PCAP/PCAPNG ingestion and flow extraction.

Usage:
    sentinel-ingest capture.pcap --output flows.jsonl
    sentinel-ingest --input capture.pcap --timeout 60.0
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from sentinel_flow_engine.aggregator import BidirectionalFlowAggregator
from sentinel_ingestion.pcap_source import PcapPacketSource


def run_pipeline(
    input_pcap: str,
    output_path: Optional[str] = None,
    timeout_sec: float = 30.0,
    output_format: str = "jsonl",
) -> int:
    """Execute the passive packet ingestion and flow aggregation pipeline."""
    pcap_path = Path(input_pcap)
    if not pcap_path.exists():
        sys.stderr.write(f"Error: Input PCAP file '{input_pcap}' does not exist.\n")
        return 1

    if output_format.lower() != "jsonl":
        sys.stderr.write(f"Error: Unsupported output format '{output_format}'. Only 'jsonl' is supported.\n")
        return 1

    out_file = None
    if output_path:
        try:
            out_file = open(output_path, "w", encoding="utf-8")
        except Exception as err:
            sys.stderr.write(f"Error: Cannot open output file '{output_path}': {err}\n")
            return 1

    packet_count = 0
    flow_count = 0
    start_wall_time = time.perf_counter()

    aggregator = BidirectionalFlowAggregator(inactivity_timeout_sec=timeout_sec)

    try:
        source = PcapPacketSource(pcap_path)
        for packet in source.stream_packets():
            packet_count += 1
            
            # 1. Ingest packet
            terminated_flow = aggregator.add_packet(packet)
            if terminated_flow is not None:
                flow_count += 1
                line = terminated_flow.to_jsonl() + "\n"
                if out_file:
                    out_file.write(line)
                else:
                    sys.stdout.write(line)

            # 2. Periodically flush expired flows based on packet timestamp
            for expired_flow in aggregator.flush_expired(packet.timestamp):
                flow_count += 1
                line = expired_flow.to_jsonl() + "\n"
                if out_file:
                    out_file.write(line)
                else:
                    sys.stdout.write(line)

        # 3. Flush remaining active flows at end-of-input
        for remaining_flow in aggregator.flush_all():
            flow_count += 1
            line = remaining_flow.to_jsonl() + "\n"
            if out_file:
                out_file.write(line)
            else:
                sys.stdout.write(line)

    except Exception as err:
        sys.stderr.write(f"Error processing PCAP: {err}\n")
        return 1
    finally:
        if out_file:
            out_file.close()

    elapsed = max(1e-6, time.perf_counter() - start_wall_time)
    pps = packet_count / elapsed
    fps = flow_count / elapsed

    sys.stderr.write(
        f"[SentinelAI] Processed {packet_count} packets into {flow_count} flows in {elapsed:.3f}s "
        f"({pps:.1f} pkts/sec, {fps:.1f} flows/sec)\n"
    )
    if output_path:
        sys.stderr.write(f"[SentinelAI] Flow records written to: {output_path}\n")

    return 0


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-ingest",
        description="SentinelAI — Passive PCAP/PCAPNG Flow Ingestion Engine",
    )
    parser.add_argument(
        "positional_input",
        nargs="?",
        default=None,
        help="Path to input PCAP or PCAPNG capture file",
    )
    parser.add_argument(
        "-i", "--input",
        dest="flag_input",
        default=None,
        help="Path to input PCAP or PCAPNG capture file",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path to output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=30.0,
        help="Flow inactivity timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "-f", "--format",
        default="jsonl",
        choices=["jsonl"],
        help="Output format (default: jsonl)",
    )

    parsed = parser.parse_args(args)
    input_file = parsed.flag_input or parsed.positional_input

    if not input_file:
        parser.print_help(sys.stderr)
        sys.stderr.write("\nError: Please provide an input PCAP file.\n")
        return 1

    return run_pipeline(
        input_pcap=input_file,
        output_path=parsed.output,
        timeout_sec=parsed.timeout,
        output_format=parsed.format,
    )


if __name__ == "__main__":
    sys.exit(main())

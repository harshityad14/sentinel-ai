#!/usr/bin/env python3
"""SentinelAI Demo Traffic Replay Script.

Ingests a PCAP file or synthetic network flows and publishes FlowRecords
into Kafka topic `sentinel.flows.raw` for real-time streaming pipeline processing.

IMPORTANT: Strictly passive operation. Reads offline PCAP captures or synthetic
telemetry only. NEVER transmits raw packets or probes target networks.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [demo_replay]: %(message)s",
)
logger = logging.getLogger("sentinel.demo_replay")

# Ensure packages are importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "packages" / "models"))
sys.path.insert(0, str(repo_root / "packages" / "ingestion"))
sys.path.insert(0, str(repo_root / "packages" / "flow_engine"))
sys.path.insert(0, str(repo_root / "packages" / "streaming"))

from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_FLOWS_RAW, get_flow_raw_partition_key


def generate_synthetic_demo_flows(count: int = 10):
    """Generates synthetic flow records for demonstration purposes."""
    flows = []
    now = datetime.now(timezone.utc)
    for i in range(count):
        flow = FlowRecord(
            flow_id=f"demo-flow-{i:04d}",
            start_time=now,
            source_ip=f"192.168.1.{10 + (i % 5)}",
            destination_ip="10.0.0.1",
            source_port=40000 + i,
            destination_port=80 if i % 2 == 0 else 443,
            protocol=ProtocolType.TCP,
            total_packets=50 + i * 2,
            total_bytes=4000 + i * 150,
            duration_sec=1.5,
            forward_packets=30 + i,
            backward_packets=20 + i,
            forward_bytes=2500 + i * 100,
            backward_bytes=1500 + i * 50,
        )
        flows.append(flow)
    return flows


def replay_flows(flows, bootstrap_servers: str, rate_per_sec: float = 5.0):
    """Replays flow records into the Kafka stream."""
    logger.info(f"Connecting to Kafka at {bootstrap_servers}...")
    producer = None
    try:
        from confluent_kafka import Producer
        producer = Producer({
            "bootstrap.servers": bootstrap_servers,
            "client.id": "sentinel-demo-replay",
        })
        logger.info("Connected to Kafka cluster.")
    except Exception as exc:
        logger.warning(f"Kafka unavailable ({exc}). Simulating replay locally.")

    sent_count = 0
    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0

    for flow in flows:
        envelope = StreamEnvelope(
            event_id=f"evt-{flow.flow_id}",
            trace_id=f"tr-{flow.flow_id}",
            schema_name="FlowRecord",
            schema_version="1.0",
            source_stage="demo_replay",
            payload=flow,
        )
        payload_bytes = envelope.to_bytes()
        partition_key = get_flow_raw_partition_key(flow.source_ip)

        if producer:
            producer.produce(
                topic=TOPIC_FLOWS_RAW,
                key=partition_key.encode("utf-8"),
                value=payload_bytes,
            )
            producer.poll(0)
        
        sent_count += 1
        logger.info(f"Replayed flow {sent_count}/{len(flows)}: {flow.flow_id} ({flow.source_ip} -> {flow.destination_ip}:{flow.destination_port})")
        if interval > 0:
            time.sleep(interval)

    if producer:
        producer.flush(timeout=5)
        logger.info("All flows flushed to Kafka.")

    logger.info(f"Replay complete. Total flows replayed: {sent_count}")


def main():
    parser = argparse.ArgumentParser(description="SentinelAI PCAP / Flow Replay Utility")
    parser.add_argument("--pcap", type=str, default=None, help="Path to PCAP capture file")
    parser.add_argument("--count", type=int, default=10, help="Number of demo flows to generate if no PCAP")
    parser.add_argument("--kafka", type=str, default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"), help="Kafka bootstrap servers")
    parser.add_argument("--rate", type=float, default=2.0, help="Replay rate in flows/sec")
    args = parser.parse_args()

    flows = []
    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            logger.error(f"PCAP file not found: {args.pcap}")
            sys.exit(1)
        logger.info(f"Parsing PCAP file: {pcap_path}...")
        try:
            from sentinel_ingestion.engine import PcapIngestionEngine
            engine = PcapIngestionEngine()
            flows = engine.process_file(str(pcap_path))
            logger.info(f"Parsed {len(flows)} flows from PCAP.")
        except Exception as exc:
            logger.error(f"Failed to process PCAP file: {exc}")
            sys.exit(1)
    else:
        logger.info(f"Generating {args.count} synthetic demo flows...")
        flows = generate_synthetic_demo_flows(args.count)

    replay_flows(flows, bootstrap_servers=args.kafka, rate_per_sec=args.rate)


if __name__ == "__main__":
    main()

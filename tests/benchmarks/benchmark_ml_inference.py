"""Phase 10 ML Inference Benchmark Utility.

Measures:
- Single-flow inference latency (mean, median/p50, p95, p99)
- Single-core sustained throughput (flows/sec)
- Feature vector extraction + ML scoring end-to-end latency
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Tuple
import numpy as np

# Ensure packages are importable when running benchmark directly
project_root = Path(__file__).resolve().parent.parent.parent
for pkg in ["models", "ingestion", "flow_engine", "features", "detection", "correlation", "streaming", "ai_agent"]:
    pkg_path = project_root / "packages" / pkg
    if pkg_path.exists() and str(pkg_path) not in sys.path:
        sys.path.insert(0, str(pkg_path))

from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_models.features import FeatureVector, NetworkFeatures, TimingFeatures
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.benchmark_ml")


from sentinel_features.extractor import UnifiedFeatureExtractor

def generate_benchmark_flows(count: int = 1000) -> List[Tuple[FlowRecord, FeatureVector]]:
    items = []
    now = datetime.now(timezone.utc)
    extractor = UnifiedFeatureExtractor()

    for i in range(count):
        flow = FlowRecord(
            flow_id=f"bench-flow-{i:05d}",
            source_ip="192.168.1.50",
            destination_ip=f"10.0.0.{i % 250 + 1}",
            source_port=40000 + (i % 10000),
            destination_port=80 if i % 2 == 0 else 443,
            protocol=ProtocolType.TCP,
            start_time=now,
            end_time=now,
            duration_sec=1.5,
            total_packets=30,
            forward_packets=10,
            backward_packets=20,
            total_bytes=4500,
            forward_bytes=1500,
            backward_bytes=3000,
            min_packet_size=40,
            max_packet_size=1500,
            mean_packet_size=150.0,
            std_packet_size=80.0,
        )
        fv = extractor.extract(flow)
        items.append((flow, fv))

    return items


def run_benchmark(flow_count: int = 1000) -> None:
    logger.info(f"Initializing RandomForestMLDetector for benchmark ({flow_count} flows)...")
    detector = RandomForestMLDetector()
    logger.info(f"Using detector: {detector.detector_name} (Model: {detector.metadata.model_name} v{detector.metadata.model_version})")

    flows = generate_benchmark_flows(flow_count)

    # Warmup
    for flow, fv in flows[:50]:
        detector.detect(flow, fv)

    # Individual flow inference latency measurements
    latencies_ms = []
    t_start = time.perf_counter()

    for flow, fv in flows:
        t0 = time.perf_counter()
        detector.detect(flow, fv)
        lat = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(lat)

    total_time = time.perf_counter() - t_start
    throughput = flow_count / max(1e-6, total_time)

    p50 = float(np.percentile(latencies_ms, 50))
    p95 = float(np.percentile(latencies_ms, 95))
    p99 = float(np.percentile(latencies_ms, 99))
    mean_lat = float(np.mean(latencies_ms))

    print("\n" + "=" * 65)
    print("        SENTINELAI ML INFERENCE BENCHMARK REPORT")
    print("=" * 65)
    print(f"Model:                     {detector.metadata.model_name} v{detector.metadata.model_version}")
    print(f"Algorithm:                 {detector.metadata.algorithm}")
    print(f"Total Flows Evaluated:     {flow_count}")
    print(f"Total Processing Time:     {total_time:.4f} s")
    print(f"Single-Core Throughput:    {throughput:.1f} flows/sec")
    print("-" * 65)
    print(f"Mean Latency:              {mean_lat:.4f} ms/flow")
    print(f"Median (p50) Latency:      {p50:.4f} ms/flow")
    print(f"p95 Latency:               {p95:.4f} ms/flow")
    print(f"p99 Latency:               {p99:.4f} ms/flow")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark ML Inference Performance.")
    parser.add_argument("--count", type=int, default=1000, help="Number of flows to benchmark")
    args = parser.parse_args()
    run_benchmark(args.count)

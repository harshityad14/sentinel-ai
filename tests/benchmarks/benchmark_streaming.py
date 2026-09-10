"""Phase 6 Real-Time Streaming Pipeline Performance Benchmark.

Measures:
- Serialization and deserialization throughput (events/sec)
- Stage processing latency percentiles: Mean, P50, P95, P99 (ms)
- Multi-stage end-to-end streaming throughput across full pipeline
- Sliding-window deduplication check throughput
"""

import argparse
from datetime import datetime, timezone
import time
from typing import List

import numpy as np

from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_streaming.bus import MemoryStreamingBus
from sentinel_streaming.reliability.deduplicator import IdempotencyDeduplicator
from sentinel_streaming.schemas import StreamEnvelope
from sentinel_streaming.topics import TOPIC_FLOWS_RAW
from sentinel_streaming.workers.alert_persistence_worker import AlertPersistenceWorker
from sentinel_streaming.workers.detection_correlation_worker import DetectionCorrelationWorker
from sentinel_streaming.workers.feature_detection_worker import FeatureDetectionWorker
from sentinel_streaming.workers.flow_feature_worker import FlowFeatureWorker


def generate_synthetic_flows(count: int = 1000) -> List[FlowRecord]:
    """Generate diverse synthetic flow records for benchmarking."""
    now = datetime.now(timezone.utc)
    flows = []
    for i in range(count):
        # 30% malicious/suspicious flows (port scan / syn flood)
        is_suspicious = (i % 3 == 0)
        flows.append(
            FlowRecord(
                flow_id=f"flow-bench-{i:06d}",
                start_time=now,
                source_ip=f"192.168.1.{10 + (i % 20)}",
                destination_ip=f"10.0.0.{5 + (i % 5)}",
                source_port=40000 + (i % 20000),
                destination_port=80 if not is_suspicious else (1000 + i % 500),
                protocol=ProtocolType.TCP,
                total_packets=100 if not is_suspicious else 300,
                total_bytes=8000 if not is_suspicious else 25000,
                duration_sec=1.5 if not is_suspicious else 0.2,
                forward_packets=60 if not is_suspicious else 280,
                backward_packets=40 if not is_suspicious else 20,
                forward_bytes=5000 if not is_suspicious else 22000,
                backward_bytes=3000 if not is_suspicious else 3000,
                tcp_flags={"syn": 20 if is_suspicious else 1, "ack": 10 if is_suspicious else 90},
                termination_reason="TIMEOUT",
            )
        )
    return flows


def run_benchmark(num_events: int = 1000) -> None:
    print("=" * 70)
    print(f"SentinelAI Phase 6 Real-Time Streaming Benchmark ({num_events} events)")
    print("=" * 70)

    flows = generate_synthetic_flows(num_events)

    # 1. Serialization Benchmark
    print("\n[1] Envelope Serialization & Deserialization Benchmark...")
    ser_times = []
    envelopes = []
    t0 = time.perf_counter()
    for f in flows:
        env = StreamEnvelope(
            event_id=f"evt-{f.flow_id}",
            trace_id=f"tr-{f.flow_id}",
            schema_name="FlowRecord",
            schema_version="1.0.0",
            source_stage="ingestion",
            payload=f,
        )
        envelopes.append(env)
        t_s = time.perf_counter()
        raw = env.to_bytes()
        ser_times.append((time.perf_counter() - t_s) * 1000.0)
    t_ser_total = time.perf_counter() - t0
    ser_throughput = num_events / t_ser_total

    deser_times = []
    raw_payloads = [e.to_bytes() for e in envelopes]
    t0 = time.perf_counter()
    for raw in raw_payloads:
        t_s = time.perf_counter()
        StreamEnvelope.from_bytes(raw, payload_cls=FlowRecord)
        deser_times.append((time.perf_counter() - t_s) * 1000.0)
    t_deser_total = time.perf_counter() - t0
    deser_throughput = num_events / t_deser_total

    print(f"  Serialization Throughput   : {ser_throughput:,.1f} events/sec")
    print(f"  Serialization Latency      : Mean={np.mean(ser_times):.3f}ms | P50={np.percentile(ser_times, 50):.3f}ms | P95={np.percentile(ser_times, 95):.3f}ms | P99={np.percentile(ser_times, 99):.3f}ms")
    print(f"  Deserialization Throughput : {deser_throughput:,.1f} events/sec")
    print(f"  Deserialization Latency    : Mean={np.mean(deser_times):.3f}ms | P50={np.percentile(deser_times, 50):.3f}ms | P95={np.percentile(deser_times, 95):.3f}ms | P99={np.percentile(deser_times, 99):.3f}ms")

    # 2. Deduplication Throughput Benchmark
    print("\n[2] Deduplication LRU Cache Benchmark...")
    dedup = IdempotencyDeduplicator(max_size=50000)
    t0 = time.perf_counter()
    for f in flows:
        dedup.check_and_record(f"evt-{f.flow_id}")
    t_dedup = time.perf_counter() - t0
    dedup_throughput = num_events / t_dedup
    print(f"  Deduplication Check Rate   : {dedup_throughput:,.1f} checks/sec")

    # 3. End-to-End Streaming Pipeline Benchmark
    print("\n[3] End-to-End Streaming Pipeline Benchmark (Flow -> Feature -> Det -> Corr -> Sink)...")
    bus = MemoryStreamingBus()
    producer = bus.create_producer()

    cons_feat = bus.create_consumer("cg-bench-feat")
    cons_det = bus.create_consumer("cg-bench-det")
    cons_corr = bus.create_consumer("cg-bench-corr")
    cons_sink = bus.create_consumer("cg-bench-sink")

    w_feat = FlowFeatureWorker(consumer=cons_feat, producer=producer)
    w_det = FeatureDetectionWorker(consumer=cons_det, producer=producer)
    w_corr = DetectionCorrelationWorker(consumer=cons_corr, producer=producer)
    w_sink = AlertPersistenceWorker(consumer=cons_sink, session_factory=None)

    w_feat.start()
    w_det.start()
    w_corr.start()
    w_sink.start()

    e2e_latencies = []
    t_pipeline_start = time.perf_counter()

    for env in envelopes:
        t_start = time.perf_counter()
        producer.produce(TOPIC_FLOWS_RAW, env.to_bytes(), key=env.payload.flow_id)

        # Stage 1: Feature Worker
        msg1 = cons_feat.poll(timeout=0.01)
        if msg1:
            w_feat.process_message(msg1)

        # Stage 2: Detection Worker
        msg2 = cons_det.poll(timeout=0.01)
        if msg2:
            w_det.process_message(msg2)

        # Stage 3: Correlation Worker
        msg3 = cons_corr.poll(timeout=0.01)
        if msg3:
            w_corr.process_message(msg3)

        # Stage 4: Sink Worker
        msg4 = cons_sink.poll(timeout=0.01)
        if msg4:
            w_sink.process_message(msg4)

        e2e_latencies.append((time.perf_counter() - t_start) * 1000.0)

    t_pipeline_total = time.perf_counter() - t_pipeline_start
    pipeline_throughput = num_events / t_pipeline_total

    print(f"  Pipeline Events Ingested   : {num_events}")
    print(f"  Pipeline Total Duration    : {t_pipeline_total:.3f} seconds")
    print(f"  Pipeline E2E Throughput    : {pipeline_throughput:,.1f} flows/sec")
    print(f"  Pipeline E2E Latency (ms)  : Mean={np.mean(e2e_latencies):.3f}ms | P50={np.percentile(e2e_latencies, 50):.3f}ms | P95={np.percentile(e2e_latencies, 95):.3f}ms | P99={np.percentile(e2e_latencies, 99):.3f}ms")
    print(f"  Workers Telemetry          : Feat={w_feat.processed_count} | Det={w_det.processed_count} | Corr={w_corr.processed_count} | Persisted={w_sink.persisted_count}")

    w_feat.stop()
    w_det.stop()
    w_corr.stop()
    w_sink.stop()

    print("\n" + "=" * 70)
    print("BENCHMARK STATUS: SUCCESS")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Phase 6 Streaming Benchmark")
    parser.add_argument("--events", type=int, default=1000, help="Number of synthetic flow events to simulate")
    args = parser.parse_args()
    run_benchmark(num_events=args.events)

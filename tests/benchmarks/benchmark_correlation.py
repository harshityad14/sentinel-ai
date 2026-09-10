"""Phase 4 Alert Correlation & Risk Scoring performance benchmark utility.

Measures:
- detections processed
- alerts generated (new vs deduplicated/updated)
- total processing time (seconds)
- detections/sec (correlation ingestion throughput)
- alerts/sec (incident generation throughput)
- average correlation latency (milliseconds)
- p99 correlation latency (milliseconds)
- memory bounds stability for sliding correlation windows
"""

import argparse
from datetime import datetime, timedelta, timezone
import time
from typing import List

import numpy as np

from sentinel_detection.correlation.config import CorrelationConfig
from sentinel_detection.correlation.correlator import AlertCorrelator
from sentinel_models.detection import (
    DetectionEvidence,
    DetectionResult,
    DetectionSeverity,
    DetectionSignal,
    DetectorType,
    ThreatType,
)


def create_synthetic_detections(num_detections: int = 10000) -> List[DetectionResult]:
    """Generate a batch of diverse synthetic DetectionResults for benchmarking."""
    detections: List[DetectionResult] = []
    base_time = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    threat_pool = [
        ThreatType.SYN_FLOOD,
        ThreatType.PORT_SCAN,
        ThreatType.C2_BEACONING,
        ThreatType.DNS_DGA,
        ThreatType.DNS_TUNNELING,
        ThreatType.DATA_EXFILTRATION,
        ThreatType.SUSPICIOUS_TLS,
        ThreatType.BEHAVIORAL_ANOMALY,
    ]

    for i in range(num_detections):
        # 10% benign flows to test filtering
        if i % 10 == 0:
            det = DetectionResult(
                detection_id=f"det_benign_{i}",
                flow_id=f"flow_{i:06d}",
                threat_type=ThreatType.BENIGN,
                detector_type=DetectorType.ENSEMBLE,
                confidence=0.0,
                severity=DetectionSeverity.INFO,
                evidence=[],
                signals=[],
                detection_timestamp=base_time + timedelta(milliseconds=i * 5),
            )
        else:
            threat = threat_pool[i % len(threat_pool)]
            # 50 unique attacker IPs to test aggregation and deduplication
            src_ip = f"192.168.1.{i % 50 + 1}"
            dst_ip = f"10.0.0.{i % 10 + 1}"
            t = base_time + timedelta(milliseconds=i * 5)

            ev = [
                DetectionEvidence(
                    feature_name="observed_rate",
                    observed_value=120.5 + (i % 10),
                    threshold_value=50.0,
                    description="Rate exceeded threshold",
                )
            ]
            sig = [
                DetectionSignal(
                    signal_id=f"sig_{i}_1",
                    threat_type=threat,
                    detector_type=DetectorType.RULE,
                    detector_name="synthetic_detector",
                    confidence=0.85,
                    severity=DetectionSeverity.HIGH,
                    evidence=ev,
                    description="Synthetic detection signal",
                )
            ]

            det = DetectionResult(
                detection_id=f"det_{i:06d}",
                flow_id=f"flow_{i:06d}",
                threat_type=threat,
                detector_type=DetectorType.RULE,
                confidence=0.85,
                severity=DetectionSeverity.HIGH,
                evidence=ev,
                signals=sig,
                detection_timestamp=t,
                explanation=f"{threat.value} observed from {src_ip}",
                context={
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": 10000 + (i % 50000),
                    "destination_port": 80,
                    "protocol": "TCP",
                },
            )
        detections.append(det)

    return detections


def run_benchmark(num_detections: int = 10000) -> None:
    """Execute Phase 4 correlation performance benchmark."""
    print("================================================================================")
    print(" SentinelAI Phase 4 — Alert Correlation & Risk Scoring Benchmark")
    print("================================================================================")
    print(f"Generating synthetic detection dataset ({num_detections:,} detections)...")

    detections = create_synthetic_detections(num_detections)
    print(f"Dataset generated: {len(detections):,} detections ready.")
    print("--------------------------------------------------------------------------------")

    config = CorrelationConfig(
        time_window_sec=60.0,
        duplicate_window_sec=20.0,
        max_signals_per_alert=50,
        max_active_groups=5000,
        max_active_alerts=5000,
    )
    correlator = AlertCorrelator(config)

    latencies_ms: List[float] = []
    new_alerts_count = 0
    updated_alerts_count = 0
    suppressed_count = 0

    t_start = time.perf_counter()

    for det in detections:
        t0 = time.perf_counter()
        alert, is_new = correlator.process_detection(det, timestamp=det.detection_timestamp)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(lat_ms)

        if alert is not None:
            if is_new:
                new_alerts_count += 1
            else:
                updated_alerts_count += 1
        else:
            suppressed_count += 1

    total_time = time.perf_counter() - t_start

    det_per_sec = num_detections / total_time
    alerts_per_sec = (new_alerts_count + updated_alerts_count) / total_time
    avg_latency = float(np.mean(latencies_ms))
    p99_latency = float(np.percentile(latencies_ms, 99))
    max_latency = float(np.max(latencies_ms))

    # Verify memory stability
    memory_stable = (
        correlator.active_alerts_count <= config.max_active_alerts
        and correlator.active_groups_count <= config.max_active_groups
    )

    print(f"Detections processed:        {num_detections:,}")
    print(f"Total processing time:       {total_time:.4f} sec")
    print(f"Detections throughput:       {det_per_sec:,.1f} detections/sec")
    print(f"Alert updates throughput:    {alerts_per_sec:,.1f} alerts/sec")
    print(f"New alerts created:          {new_alerts_count:,}")
    print(f"Existing alerts aggregated:  {updated_alerts_count:,} (deduplicated)")
    print(f"Benign / suppressed:         {suppressed_count:,}")
    print("--------------------------------------------------------------------------------")
    print(f"Average correlation latency: {avg_latency:.4f} ms/detection")
    print(f"P99 correlation latency:     {p99_latency:.4f} ms/detection")
    print(f"Worst-case latency:          {max_latency:.4f} ms/detection")
    print(f"Active alerts in cache:      {correlator.active_alerts_count:,} (cap: {config.max_active_alerts:,})")
    print(f"Active groups in cache:      {correlator.active_groups_count:,} (cap: {config.max_active_groups:,})")
    print(f"Memory stability:            {'PASS' if memory_stable else 'FAIL'}")
    print("================================================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Phase 4 Correlation Benchmark")
    parser.add_argument("-n", "--num-detections", type=int, default=10000, help="Number of detections")
    args = parser.parse_args()
    run_benchmark(args.num_detections)

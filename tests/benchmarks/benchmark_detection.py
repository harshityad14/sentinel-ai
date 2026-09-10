"""Phase 3 Hybrid Threat Detection Engine performance benchmark utility.

Measures:
- flows processed
- detections generated (threat vs benign)
- total processing time (seconds)
- flows/sec (detection throughput)
- average detection latency (milliseconds/flow)
- detector category benchmarks (Rules, Statistical, ML, Ensemble Pipeline)
"""

import argparse
from datetime import datetime, timezone
import time
from typing import List, Tuple

from sentinel_detection.pipeline import DetectionPipeline, create_default_detection_pipeline
from sentinel_detection.rules import (
    C2BeaconingRuleDetector,
    DataExfiltrationRuleDetector,
    DNSDGARuleDetector,
    DNSTunnelingRuleDetector,
    PortScanRuleDetector,
    SuspiciousTLSRuleDetector,
    SYNFloodRuleDetector,
    UDPFloodRuleDetector,
)
from sentinel_detection.statistical.anomaly_detector import StatisticalAnomalyDetector
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_features.extractor import UnifiedFeatureExtractor
from sentinel_models.events import DNSMetadata, FlowRecord, ProtocolType, TLSMetadata
from sentinel_models.features import FeatureVector


def create_synthetic_flow_dataset(num_flows: int = 5000) -> Tuple[List[FlowRecord], List[FeatureVector]]:
    """Generate diverse synthetic flows and corresponding FeatureVectors."""
    flows: List[FlowRecord] = []
    now = datetime.now(timezone.utc)
    extractor = UnifiedFeatureExtractor()

    for i in range(num_flows):
        scenario = i % 10
        is_tcp = scenario not in (2, 5)

        # Diverse scenarios: benign web, benign streaming, syn flood, udp flood, dga, c2, etc.
        if scenario == 1:
            # SYN flood profile
            flags = {"syn": 80, "ack": 1, "fin": 0, "rst": 0, "psh": 0, "urg": 0, "ece": 0, "cwr": 0}
            tot_pkts = 81
            fwd_pkts = 80
            bwd_pkts = 1
            tot_bytes = 4800
            fwd_bytes = 4800
            bwd_bytes = 0
            duration = 1.0
            dns_ctx, tls_ctx = None, None
            dst_port = 80
            proto = ProtocolType.TCP
        elif scenario == 2:
            # UDP flood profile
            flags = {}
            tot_pkts = 200
            fwd_pkts = 200
            bwd_pkts = 0
            tot_bytes = 100000
            fwd_bytes = 100000
            bwd_bytes = 0
            duration = 1.0
            dns_ctx, tls_ctx = None, None
            dst_port = 53
            proto = ProtocolType.UDP
        elif scenario == 3:
            # DNS DGA profile
            flags = {}
            tot_pkts = 2
            fwd_pkts = 1
            bwd_pkts = 1
            tot_bytes = 200
            fwd_bytes = 100
            bwd_bytes = 100
            duration = 0.05
            dns_ctx = DNSMetadata(query_name=f"x78kjq98zmpq{i}d.biz", query_type="A", response_code="NXDOMAIN")
            tls_ctx = None
            dst_port = 53
            proto = ProtocolType.UDP
        elif scenario == 4:
            # Suspicious TLS (deprecated version)
            flags = {"syn": 1, "ack": 5, "fin": 1, "rst": 0, "psh": 2, "urg": 0, "ece": 0, "cwr": 0}
            tot_pkts = 10
            fwd_pkts = 5
            bwd_pkts = 5
            tot_bytes = 2000
            fwd_bytes = 1000
            bwd_bytes = 1000
            duration = 0.5
            dns_ctx = None
            tls_ctx = TLSMetadata(sni="oldserver.corp", version="TLS 1.0", ja3="771,4865,43-51,29,0")
            dst_port = 443
            proto = ProtocolType.TCP
        else:
            # Benign normal traffic
            flags = {"syn": 1, "ack": 15, "fin": 1, "rst": 0, "psh": 5, "urg": 0, "ece": 0, "cwr": 0} if is_tcp else {}
            tot_pkts = 20
            fwd_pkts = 10
            bwd_pkts = 10
            tot_bytes = 6000
            fwd_bytes = 3000
            bwd_bytes = 3000
            duration = 4.0
            dns_ctx = DNSMetadata(query_name="www.google.com", query_type="A", response_code="NOERROR") if scenario == 5 else None
            tls_ctx = TLSMetadata(sni="www.google.com", version="TLS 1.3", ja3="771,4865,43-51,29,0") if is_tcp else None
            dst_port = 443 if is_tcp else 53
            proto = ProtocolType.TCP if is_tcp else ProtocolType.UDP

        flow = FlowRecord(
            flow_id=f"flow_{i:06d}",
            start_time=now,
            end_time=now,
            duration_sec=duration,
            source_ip=f"192.168.1.{i % 250 + 1}",
            destination_ip="10.0.0.1",
            source_port=10000 + (i % 50000),
            destination_port=dst_port,
            protocol=proto,
            total_packets=tot_pkts,
            forward_packets=fwd_pkts,
            backward_packets=bwd_pkts,
            total_bytes=tot_bytes,
            forward_bytes=fwd_bytes,
            backward_bytes=bwd_bytes,
            min_packet_size=40,
            max_packet_size=1500,
            mean_packet_size=float(tot_bytes) / max(1, tot_pkts),
            std_packet_size=50.0,
            tcp_flags=flags,
            dns_context=dns_ctx,
            tls_context=tls_ctx,
        )
        flows.append(flow)

    feature_vectors = [extractor.extract(f) for f in flows]
    return flows, feature_vectors


def run_benchmark(num_flows: int = 5000) -> None:
    """Execute Phase 3 detection performance benchmark."""
    print("================================================================================")
    print(" SentinelAI Phase 3 — Hybrid Threat Detection Engine Benchmark")
    print("================================================================================")
    print(f"Generating synthetic evaluation dataset ({num_flows:,} flows)...")

    flows, features = create_synthetic_flow_dataset(num_flows)
    print(f"Dataset generated: {len(flows):,} flow records + feature vectors ready.")
    print("--------------------------------------------------------------------------------")

    # 1. Benchmark Rule Engine Alone (8 rule detectors)
    rule_pipeline = DetectionPipeline([
        SYNFloodRuleDetector(),
        UDPFloodRuleDetector(),
        PortScanRuleDetector(),
        DNSDGARuleDetector(),
        DNSTunnelingRuleDetector(),
        C2BeaconingRuleDetector(),
        DataExfiltrationRuleDetector(),
        SuspiciousTLSRuleDetector(),
    ])
    t0 = time.perf_counter()
    rule_threats = 0
    for flow, fv in zip(flows, features):
        res = rule_pipeline.analyze(flow, fv)
        if res.is_threat:
            rule_threats += 1
    t_rule = time.perf_counter() - t0
    rule_fps = num_flows / t_rule
    rule_latency_ms = (t_rule / num_flows) * 1000.0

    print(f"1. Rule Engine (8 detectors):")
    print(f"   - Processed:        {num_flows:,} flows")
    print(f"   - Detections:       {rule_threats:,} threat signals")
    print(f"   - Time:             {t_rule:.4f} sec")
    print(f"   - Throughput:       {rule_fps:,.1f} flows/sec")
    print(f"   - Latency:          {rule_latency_ms:.4f} ms/flow")
    print("--------------------------------------------------------------------------------")

    # 2. Benchmark Statistical Anomaly Detector Alone
    stat_pipeline = DetectionPipeline([StatisticalAnomalyDetector()])
    t0 = time.perf_counter()
    stat_threats = 0
    for flow, fv in zip(flows, features):
        res = stat_pipeline.analyze(flow, fv)
        if res.is_threat:
            stat_threats += 1
    t_stat = time.perf_counter() - t0
    stat_fps = num_flows / t_stat
    stat_latency_ms = (t_stat / num_flows) * 1000.0

    print(f"2. Statistical Anomaly Detector (Z-score profiling):")
    print(f"   - Processed:        {num_flows:,} flows")
    print(f"   - Detections:       {stat_threats:,} threat signals")
    print(f"   - Time:             {t_stat:.4f} sec")
    print(f"   - Throughput:       {stat_fps:,.1f} flows/sec")
    print(f"   - Latency:          {stat_latency_ms:.4f} ms/flow")
    print("--------------------------------------------------------------------------------")

    # 3. Benchmark ML Supervised Inference Alone
    ml_pipeline = DetectionPipeline([RandomForestMLDetector()])
    t0 = time.perf_counter()
    ml_threats = 0
    for flow, fv in zip(flows, features):
        res = ml_pipeline.analyze(flow, fv)
        if res.is_threat:
            ml_threats += 1
    t_ml = time.perf_counter() - t0
    ml_fps = num_flows / t_ml
    ml_latency_ms = (t_ml / num_flows) * 1000.0

    print(f"3. Supervised ML Classifier (Random Forest inference):")
    print(f"   - Processed:        {num_flows:,} flows")
    print(f"   - Detections:       {ml_threats:,} threat signals")
    print(f"   - Time:             {t_ml:.4f} sec")
    print(f"   - Throughput:       {ml_fps:,.1f} flows/sec")
    print(f"   - Latency:          {ml_latency_ms:.4f} ms/flow")
    print("--------------------------------------------------------------------------------")

    # 4. Benchmark Full Hybrid Detection Pipeline (Rules + Statistical + ML + Ensemble)
    full_pipeline = create_default_detection_pipeline()
    t0 = time.perf_counter()
    total_threats = 0
    threat_breakdown = {}

    for flow, fv in zip(flows, features):
        res = full_pipeline.analyze(flow, fv)
        if res.is_threat:
            total_threats += 1
            threat_breakdown[res.threat_type.value] = threat_breakdown.get(res.threat_type.value, 0) + 1

    t_full = time.perf_counter() - t0
    full_fps = num_flows / t_full
    full_latency_ms = (t_full / num_flows) * 1000.0

    print(f"4. Full Hybrid Detection Pipeline (Ensemble + 10 Detectors):")
    print(f"   - Processed:        {num_flows:,} flows")
    print(f"   - Threat Results:   {total_threats:,} ({total_threats / num_flows:.1%})")
    print(f"   - Benign Results:   {num_flows - total_threats:,} ({(num_flows - total_threats) / num_flows:.1%})")
    print(f"   - Total Time:       {t_full:.4f} sec")
    print(f"   - Throughput:       {full_fps:,.1f} flows/sec")
    print(f"   - Average Latency:  {full_latency_ms:.4f} ms/flow")
    print("   - Threat Breakdown:")
    for threat_name, count in sorted(threat_breakdown.items(), key=lambda x: x[1], reverse=True):
        print(f"       * {threat_name:<22}: {count:>5} detections")
    print("================================================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Phase 3 Detection Benchmark")
    parser.add_argument("-n", "--num-flows", type=int, default=5000, help="Number of flows to benchmark")
    args = parser.parse_args()
    run_benchmark(args.num_flows)

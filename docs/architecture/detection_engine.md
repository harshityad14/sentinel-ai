# SentinelAI — Hybrid Threat Detection Engine Architecture

## 1. Architectural Overview

SentinelAI implements a **hybrid multi-strategy threat detection engine** that consumes bidirectional `FlowRecord` and extracted `FeatureVector` telemetry from Phase 1 and Phase 2, emitting strongly-typed `DetectionResult` outputs.

```
                           FlowRecord + FeatureVector
                                       │
                ┌──────────────────────┼──────────────────────┐
                ▼                      ▼                      ▼
        1. Rule Engine         2. Statistical         3. Supervised ML
           (8 Detectors)          Anomaly Detector       Inference Engine
                │                      │                      │
                └──────────────────────┼──────────────────────┘
                                       ▼
                            Individual DetectionSignals
                                       │
                                       ▼
                            4. Correlation & Ensemble
                               (Weighted Fusion & Bonus)
                                       │
                                       ▼
                            Consolidated DetectionResult
```

### Absolute Passive Security Invariant
All detectors operate purely on passively observed flow metadata and pre-extracted statistical features. The detection engine:
- **Never** injects or transmits packets.
- **Never** creates network sockets or outbound API requests.
- **Never** performs active scanning or endpoint probing.
- **Never** decrypts application payloads or TLS streams.

---

## 2. Core Detection Domain Models

Defined in `sentinel_models.detection`:

- `ThreatType`: Canonical threat categories:
  - `BENIGN`: Normal network traffic.
  - `SYN_FLOOD`: TCP SYN volumetric burst / DoS attack.
  - `UDP_FLOOD`: High-rate UDP volumetric flood.
  - `PORT_SCAN`: Multi-port reconnaissance / connection probe sweep.
  - `C2_BEACONING`: Periodic outbound heartbeats with minimal timing variance.
  - `DNS_DGA`: Algorithmic domain name generation with elevated entropy.
  - `DNS_TUNNELING`: Data encapsulation inside DNS queries and subdomain labels.
  - `SUSPICIOUS_TLS`: Deprecated TLS protocols, missing SNI, or anomalous fingerprints.
  - `DATA_EXFILTRATION`: Bulk outbound data transfer with extreme directional asymmetry.
  - `BEHAVIORAL_ANOMALY`: Multi-metric statistical baseline outlier ($|z| \ge 3.5$).

- `DetectorType`: Categorical origin:
  - `RULE`: Deterministic heuristic baseline.
  - `STATISTICAL`: Unsupervised statistical baseline / Z-score profiler.
  - `ML`: Supervised machine learning classifier.
  - `ENSEMBLE`: Correlated consensus across multiple detectors.

- `DetectionSeverity`: Operational impact rating:
  - `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

- `DetectionEvidence`: Machine-readable evidence item traceable to actual features:
  - `feature_name`: Triggering feature identifier (e.g. `tcp_syn_count`, `net_bytes_per_second`).
  - `observed_value`: Exact numerical or string value measured from the flow.
  - `threshold_value`: Configured rule or statistical threshold.
  - `description`: Plain-text rationale explaining why the value indicates malicious or anomalous activity.

- `DetectionSignal`: Atomic finding produced by an individual detector.
- `DetectionResult`: Correlated output retaining consensus classification and all contributing signals.

---

## 3. Detector Subsystems

### 3.1 Rule-Based Detectors (`sentinel_detection/rules/`)

Deterministic, configurable, sub-millisecond evaluation:

1. **`SYNFloodRuleDetector` (`syn_flood.py`)**:
   - Features: `tcp.syn_count`, `tcp.syn_ack_ratio`, `network.packets_per_second`.
   - Thresholds: Default `min_syn_count=20`, `min_syn_ack_ratio=5.0`, `min_pps=30.0`.
   - Rationale: Legitimate TCP connections maintain a balanced SYN-to-ACK ratio (~1:1). High SYN rates with minimal ACK receipts characterize SYN flood DoS.

2. **`UDPFloodRuleDetector` (`udp_flood.py`)**:
   - Features: `network.total_packets`, `network.packets_per_second`, `network.bytes_per_second`.
   - Thresholds: Default `min_packets=100`, `min_pps=50.0`, `min_bps=20,000.0`.
   - Rationale: High-frequency UDP bursts without prior handshake indicate UDP flooding.

3. **`PortScanRuleDetector` (`port_scan.py`)**:
   - Features: `network.duration_sec`, `network.total_packets`, `tcp.rst_count`, `context.scanned_ports_count`.
   - Thresholds: Default `min_scanned_ports=10`, `max_probe_duration_sec=2.0`.
   - Rationale: A single flow cannot confirm a port scan. The detector consumes multi-flow host context (fan-out counts) to verify scanner activity, avoiding false positives on transient failed connections.

4. **`DNSDGARuleDetector` (`dns_dga.py`)**:
   - Features: `dns.shannon_entropy`, `dns.digit_ratio`, `dns.query_length`, `dns.is_nxdomain`.
   - Thresholds: Default `min_entropy=3.65`, `min_digit_ratio=0.15`, `min_query_length=12`.
   - Rationale: Algorithmic pseudo-random domains exhibit elevated character entropy ($> 3.65$ bits/char) and abnormal digit ratios compared to natural language domains.

5. **`DNSTunnelingRuleDetector` (`dns_tunneling.py`)**:
   - Features: `dns.query_length`, `dns.subdomain_depth`, `dns.unique_char_ratio`.
   - Thresholds: Default `min_query_length=60`, `min_subdomain_depth=4`, `min_unique_char_ratio=0.55`.
   - Rationale: DNS exfiltration tools encode binary data inside concatenated subdomain labels, creating abnormally long queries with high unique character density.

6. **`C2BeaconingRuleDetector` (`c2_beaconing.py`)**:
   - Features: `timing.jitter_ratio`, `timing.mean_inter_arrival_sec`, `network.total_packets`.
   - Thresholds: Default `max_jitter_ratio=0.15`, `min_packets=6`, interval $[1.0\text{s}, 300.0\text{s}]$.
   - Rationale: Programmatically automated C2 agents beacon at strict periodic intervals, displaying near-zero timing jitter ($< 15\%$), while normal user interactions display high variance.

7. **`DataExfiltrationRuleDetector` (`data_exfiltration.py`)**:
   - Features: `network.forward_bytes`, `network.byte_asymmetry_ratio`, `network.bytes_per_second`.
   - Thresholds: Default `min_outbound_bytes=250,000`, `min_byte_asymmetry_ratio=0.85`, `min_bps=5,000.0`.
   - Rationale: Severe directional asymmetry ($> 85\%$ outbound bytes) combined with high byte volume indicates bulk data transfer or unauthorized exfiltration.

8. **`SuspiciousTLSRuleDetector` (`suspicious_tls.py`)**:
   - Features: `tls.tls_version`, `tls.sni_present`, `tls.cipher_suite_count`, `tls.ja3_hash`.
   - Thresholds: Deprecated TLS check, missing SNI on port 443, cipher suite count $< 2$, blacklisted JA3 hashes.
   - Rationale: Modern browsers offer TLS 1.2/1.3 with 15+ ciphers and SNI. Deprecated versions (SSL 3.0, TLS 1.0) and missing SNI on HTTPS reflect legacy or malicious automated agents.

---

### 3.2 Statistical Anomaly Detection (`sentinel_detection/statistical/`)

Implemented in `StatisticalAnomalyDetector` (`anomaly_detector.py`):
- **Robust Z-Score Profiling:** Measures how many standard deviations a flow feature deviates from the established baseline:
  $$z = \frac{\text{observed} - \mu}{\max(\sigma, 10^{-4})}$$
- **Monitored Dimensions:** `network.duration_sec`, `network.bytes_per_second`, `network.packets_per_second`, `network.mean_packet_size`, `network.forward_bytes`, and `timing.mean_inter_arrival_sec`.
- **Thresholding:** Default trigger threshold is $|z| \ge 3.5$.
- **Dynamic Baseline Adaptation:** Includes `update_baseline(feature_vectors)` to compute moving mean and sample standard deviation from normal operational traffic.
- **Explainability:** Emits machine-readable evidence items recording baseline $\mu$, baseline $\sigma$, observed value, and calculated Z-score for each deviating dimension.

---

### 3.3 Supervised Machine Learning (`sentinel_detection/ml/`)

Decoupled into:
- `model_metadata.py`: `MLModelMetadata` schema tracking model name, semantic version, feature ordering, and explicit status declaration.
- `trainer.py`: Standalone offline training utility (`create_deterministic_baseline_model`, `save_model_artifacts`) ensuring runtime inference does not depend on training pipelines.
- `random_forest_detector.py`: `RandomForestMLDetector`:
  - **Feature Ordering Validation:** Re-orders flattened feature dictionaries strictly according to `metadata.feature_names`.
  - **Missing Feature Imputation:** Gracefully imputes missing or `None` features with neutral default values ($0.0$) and records imputed features in metadata.
  - **Probabilistic Inference:** Calls `predict_proba()` to extract class probabilities across all target threat categories.
  - **Explainability:** Calculates decision factor contributions based on model `feature_importances_` to provide machine-readable evidence without external black-box dependencies.

> [!IMPORTANT]
> **No Fake AI Declaration:** SentinelAI strictly distinguishes implemented inference infrastructure from trained model performance. The included baseline model fixture validates deterministic runtime inference; production weights require training on verified historical PCAP datasets.

---

## 4. Ensemble & Correlation Layer

Implemented in `EnsembleCorrelationEngine` (`sentinel_detection/correlation/ensemble.py`):

### 4.1 Weighted Fusion Formula
Individual signals are grouped by `ThreatType`. For each candidate threat, the base confidence is computed via weighted combination across contributing detector types:

$$\text{Base Confidence} = \frac{\sum_{t \in T} w_t \cdot \max_{s \in S_t}(C_s)}{\sum_{t \in T} w_t}$$

Default detector weights:
- $\text{Rule Detectors } (w_{\text{RULE}}): 0.45$
- $\text{ML Classifiers } (w_{\text{ML}}): 0.35$
- $\text{Statistical Profilers } (w_{\text{STATISTICAL}}): 0.20$

### 4.2 Multi-Detector Agreement Bonus
When distinct detector categories independently agree on the same threat, an agreement bonus is applied:

$$\text{Combined Confidence} = \min\left(0.99, \, \text{Base Confidence} + (|T| - 1) \times \text{agreement\_bonus}\right)$$

Default `agreement_bonus = 0.10`.

### 4.3 Signal Preservation & Traceability
The winning consensus threat is chosen based on maximum combined confidence. Crucially, **all individual contributing signals are retained** in `DetectionResult.signals`, ensuring analysts can inspect every rule, anomaly, and ML score that led to the alert.

---

## 5. Confidence vs Severity Policy

Implemented in `sentinel_detection/scoring/severity_policy.py`:

- **Confidence:** How mathematically certain the detector is that its specific pattern was observed ($0.0 - 1.0$).
- **Severity:** The potential operational harm and business impact of the threat.

**Principle:** High confidence does NOT automatically imply CRITICAL severity. A detector may have 99% confidence in a low-impact port probe (Severity: LOW), while a suspected multi-gigabit SYN flood warrants CRITICAL severity even at 85% confidence.

### Escalation Guidelines
- `PORT_SCAN`: Baseline LOW; escalates to MEDIUM (15+ ports) or HIGH (50+ ports) upon verified fan-out.
- `SYN_FLOOD` / `UDP_FLOOD`: Baseline HIGH; escalates to CRITICAL for extreme volumes ($> 500$ packets or $> 500$ PPS).
- `DATA_EXFILTRATION`: Baseline HIGH; escalates to CRITICAL when outbound transfer exceeds 100 MB.
- `C2_BEACONING`: Baseline HIGH; escalates to CRITICAL for high confidence ($> 0.90$) with $10+$ confirmed recurrences.

---

## 6. False Positive Controls

1. **Configurable Thresholds:** Every rule detector and statistical threshold can be modified at initialization or dynamically via pipeline configuration.
2. **Selective Detector Enable/Disable:** The `DetectionPipeline` provides `enable_detector(name)` and `disable_detector(name)` to suppress noisy checks in specific environments.
3. **Consensus Confidence Gating:** The ensemble correlation layer enforces a `min_consensus_confidence` threshold (default 0.50). Signals falling below this are marked `BENIGN` with `INFO` severity.
4. **Context-Aware Suppression:** Built-in protocol filtering suppresses false alarms on legitimate periodic protocols (e.g. NTP on UDP 123 for C2 beaconing).

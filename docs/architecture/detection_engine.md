# SentinelAI — Detection Subsystem Architecture

## 1. Architectural Strategy

SentinelAI utilizes a **hybrid multi-strategy detection architecture**. Cyber attacks span diverse behavioral profiles—from high-velocity volumetric floods to low-and-slow stealth beaconing. A single detection paradigm cannot effectively address this spectrum.

To maximize precision while keeping the architecture maintainable for a solo developer, the detection subsystem enforces strict decoupling into five autonomous stages:

```
                  Enriched Flow & Feature Vectors
                               │
       ┌───────────────────────┼───────────────────────┐
       ▼                       ▼                       ▼
1. Rule-Based           2. Statistical          3. Supervised ML
   Detectors               Anomalies               Classifiers
   (Fast/Deterministic)    (Baseline Deviations)   (Encrypted Patterns)
       │                       │                       │
       └───────────────────────┼───────────────────────┘
                               ▼
                   4. Correlation Engine
                      (Attack Graphs & Deduplication)
                               │
                               ▼
                   5. Multi-Factor Risk Scoring
                               │
                               ▼
                    Explainable SOC Alert
```

---

## 2. Decoupled Detection Modules

### 2.1 Rule-Based Detection (`sentinel_detection/rules/`)
- **Philosophy:** Deterministic, low-latency evaluation for known structural violations, scanner signatures, and volumetric floods.
- **Characteristics:** Zero false positives for well-defined threshold violations; sub-millisecond execution.
- **Key Modules:**
  - `port_scan_detector.py`: Detects horizontal scans (one port across many IPs), vertical scans (many ports on one IP), and stealth SYN scans by tracking failed TCP handshakes (SYN without ACK, excessive RST receipts) per source IP within a sliding time window.
  - `ddos_detector.py`: Identifies SYN flood attacks (excessive SYN rate with high unacknowledged ratio), UDP packet floods, and ICMP broadcast reflection.

### 2.2 Statistical & Anomaly Detection (`sentinel_detection/statistical/`)
- **Philosophy:** Detects behavioral irregularities without pre-existing attack signatures by modeling expected network rhythms.
- **Characteristics:** Unsupervised, adaptive, resilient against novel malware variants.
- **Key Modules:**
  - `beaconing_detector.py`: Analyzes inter-arrival time sequences across repeated connections to identical destination endpoints. Calculates timing jitter and autocorrelation to surface periodic heartbeats characteristic of C2 malware (e.g., Cobalt Strike, Mythic).
  - `dns_detector.py`: Evaluates domain name Shannon entropy, consonant-to-vowel ratios, and query frequency distributions to detect Domain Generation Algorithms (DGA) and DNS tunneling exfiltration.
  - `baseline_profiler.py`: Maintains running exponential moving averages (EMA) of hourly data transfer volumes and connection counts per host, flagging statistical Z-score outliers ($Z > 3.5$).

### 2.3 Supervised Machine Learning (`sentinel_detection/ml/`)
- **Philosophy:** Classifies complex non-linear feature interactions in encrypted traffic without decrypting payloads.
- **Characteristics:** Lightweight, tabular gradient boosting (XGBoost/LightGBM) or Random Forest inference.
- **Key Modules:**
  - `encrypted_flow_classifier.py`: Evaluates SPLT sequences, JA3/JA4 hash frequencies, and negotiated cipher suites to distinguish benign encrypted browsing from malicious encrypted tunneling or proxy usage.

### 2.4 Correlation & Attack Graph Engine (`sentinel_detection/correlation/`)
- **Philosophy:** Converts isolated alerts into cohesive, multi-stage security incidents.
- **Functions:**
  - **Deduplication:** Merges repeated detections of the same ongoing event into a single active incident with incremented counters.
  - **Attack Chain Linking:** Correlates multi-phase activities (e.g., Reconnaissance [Port Scan] followed by Weaponization [C2 Beacon] followed by Exfiltration [High Outbound Volume]).
  - **MITRE ATT&CK Tagging:** Associates each correlated alert with standardized Tactics (TA0007, TA0011, TA0010) and Techniques (T1046, T1071, T1048).

### 2.5 Multi-Factor Risk Scoring (`sentinel_detection/scoring/`)
- **Philosophy:** Computes an objective, explainable risk score ($0 \le \text{Score} \le 100$) to prioritize analyst attention.
- **Formula:**
  $$\text{RiskScore} = \min\left(100, \, \left( \sum_{i} w_i \cdot C_i \right) \times A_{\text{target}} \times P_{\text{persistence}} \right)$$
  where:
  - $w_i$: Base severity weight for detector $i$ (Low = 20, Medium = 50, High = 80, Critical = 100).
  - $C_i$: Confidence probability of detector $i$ ($0.0 - 1.0$).
  - $A_{\text{target}}$: Asset criticality multiplier (Default workstation = 1.0, Internal server = 1.25, Core gateway/DC = 1.5).
  - $P_{\text{persistence}}$: Temporal recurrence factor (scales up for ongoing, unresolved threats).

---

## 3. Explainability & Evidence Schema

Every emitted alert is accompanied by an immutable **Evidence Payload** ensuring total transparency for human analysts and the advisory GenAI assistant:

```json
{
  "alert_id": "alt_01hx7e8b91...",
  "timestamp": "2026-09-10T17:50:00Z",
  "category": "C2_BEACONING",
  "severity": "HIGH",
  "confidence": 0.92,
  "risk_score": 88,
  "mitre_attack": {
    "tactic": "Command and Control",
    "tactic_id": "TA0011",
    "technique": "Application Layer Protocol",
    "technique_id": "T1071.001"
  },
  "source_ip": "192.168.1.105",
  "destination_ip": "198.51.100.42",
  "destination_port": 443,
  "protocol": "TCP",
  "evidence": {
    "total_connections": 142,
    "mean_interval_sec": 30.04,
    "interval_jitter_pct": 2.1,
    "payload_size_variance": 0.0,
    "ja3_fingerprint": "6734f37431670b3ab4292b8f60f29984"
  },
  "explanation": "Host established 142 periodic outbound connections with nearly zero timing jitter (2.1%) and identical packet sizes, matching Cobalt Strike default beacon profile."
}
```

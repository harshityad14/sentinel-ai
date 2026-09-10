# SentinelAI — System Overview & Architectural Topology

## 1. Executive Concept

**SentinelAI** is an AI-powered passive network threat detection and Security Operations Center (SOC) platform built for **SIH 2026 Problem 145**.

It operates on the principle that modern cyber threats—ranging from stealthy C2 channels and DNS exfiltration to volumetric DDoS—can be identified rapidly, accurately, and without invasive measures by analyzing network metadata, flow kinetics, and statistical anomalies.

---

## 2. Core Architectural Invariant

All platform components are bound by our foundational security invariant:

> **"The SentinelAI detection pipeline is strictly passive. No component may transmit packets, perform active probing, complete network handshakes, block traffic, or decrypt application payloads."**

This ensures:
- Safe operation in sensitive enterprise, industrial, and government networks.
- Absolute isolation: zero risk of introducing network instability, disrupting active production connections, or leaking monitor presence to adversaries.
- Compliance with data privacy and non-interception standards.

---

## 3. Subsystem Breakdown

```
+-------------------------------------------------------------------------+
|                               SentinelAI                                |
+-------------------------------------------------------------------------+
| [apps/web]           React + Vite + TypeScript SOC Dashboard            |
|                      (Live Alert Feed, Flow Inspector, Threat Radar)     |
+-------------------------------------------------------------------------+
| [apps/api]           FastAPI REST & WebSocket Hub                       |
|                      (Alert API, Telemetry Streams, Advisory Endpoint)   |
+-------------------------------------------------------------------------+
| [packages/ai_agent]  Advisory GenAI Security Analyst                    |
|                      (Contextual Triage, Explanations, Playbooks)       |
+-------------------------------------------------------------------------+
| [packages/detection] Multi-Strategy Detection Subsystem                 |
|                      |-- Rules (Threshold & Signature Matching)         |
|                      |-- Statistical (Jitter, Baseline, Entropy)        |
|                      |-- Machine Learning (Encrypted Flow Inference)    |
|                      |-- Correlation (Attack Graph & Deduplication)     |
|                      +-- Scoring (Multi-Factor Risk Engine)             |
+-------------------------------------------------------------------------+
| [Phase 6 Streaming]  Planned Production Kafka Event Backbone            |
+-------------------------------------------------------------------------+
| [packages/features]  Feature Extraction (SPLT, Jitter, Entropy, Ratios)  |
+-------------------------------------------------------------------------+
| [packages/flow_engine] 5-Tuple Bi-directional Flow Sessionization       |
+-------------------------------------------------------------------------+
| [packages/ingestion] Passive Packet Capture & Raw Protocol Header Parser|
+-------------------------------------------------------------------------+
| [packages/models]    Canonical Domain Schemas (Pydantic Models)         |
+-------------------------------------------------------------------------+
```

### 3.1 Ingestion Layer (`packages/ingestion`)
- Listens passively on designated network interfaces or parses offline PCAP files.
- Decodes L2/L3/L4 protocol headers (Ethernet, IPv4/IPv6, TCP, UDP, ICMP).
- Extracts unencrypted application handshake metadata:
  - DNS: Query name, query type, response codes, record counts.
  - TLS: ClientHello/ServerHello, SNI (Server Name Indication), supported cipher suites, TLS extensions, JA3/JA4 fingerprint calculation.

### 3.2 Flow Engine (`packages/flow_engine`)
- Assembles individual packets into stateful bi-directional 5-tuple sessions:
  $$\text{Key} = (\min(\text{IP}_a, \text{IP}_b), \max(\text{IP}_a, \text{IP}_b), \text{Port}_a, \text{Port}_b, \text{Proto})$$
- Tracks session lifecycles with sliding active and inactive timeouts.
- Records cumulative flow metrics: duration, total bytes in both directions, total packets, and TCP flag transitions.

### 3.3 Feature Extraction (`packages/features`)
- Computes statistical and temporal features per flow:
  - **Sequence of Packet Lengths and Times (SPLT):** Captures application layer protocol behavior without decryption.
  - **Inter-Arrival Jitter:** Standard deviation and autocorrelation of packet timing intervals.
  - **Entropy:** Shannon entropy over domain names and byte frequencies.
  - **Directional Volume Asymmetry:** $\frac{\text{Bytes}_{\text{forward}}}{\text{Bytes}_{\text{backward}}}$ and packet size distributions.

### 3.4 Detection Subsystem (`packages/detection`)
Maintains decoupled modules for independent execution and testing:
- **Rule-based:** Immediate triggers for well-defined protocol violations, port scans, and volumetric floods.
- **Statistical / Baseline:** Anomaly detection comparing current flow metrics against dynamic host/network baselines.
- **Supervised ML:** Pre-trained classifiers for encrypted traffic analysis and behavioral patterns.
- **Correlation:** Deduplicates alerts into unified incidents and maps multi-stage kill chains.
- **Scoring:** Assigns a composite risk score (0 — 100) based on severity, confidence, and target criticality.

### 3.5 Advisory GenAI Security Analyst (`packages/ai_agent`)
- Ingests correlated alerts and technical evidence.
- Generates natural language incident descriptions, impact analyses, and actionable remediation playbooks for human SOC analysts.
- **Strict Boundary:** Never classifies threats or overrides detection engine decisions.

### 3.6 API & SOC Dashboard (`apps/api` & `apps/web`)
- FastAPI service providing high-performance REST endpoints and WebSocket channels.
- React-based dashboard providing real-time visualization of active threats, network telemetry, and deep-dive flow inspection.

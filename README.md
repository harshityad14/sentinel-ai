# SentinelAI 🛡️

**AI-Powered Passive Network Threat Detection & Security Operations Platform**  
*Built for Smart India Hackathon (SIH) 2026 — Problem 145*

---

## 🎯 Executive Summary

**SentinelAI** is a production-grade, passive network threat detection platform designed to ingest raw packet streams and flow records, extract rich behavioral metadata without payload decryption, detect advanced cyber threats in near real-time, generate explainable high-confidence alerts, and surface contextual threat intelligence through an interactive SOC dashboard.

### 🔒 Core Architectural Invariant
> **The SentinelAI detection pipeline is strictly passive. No component may transmit packets, perform active probing, complete network handshakes, block traffic, or decrypt application payloads.**

All detection mechanisms rely exclusively on protocol header metadata, flow statistics, packet length and timing sequences (SPLT), DNS query telemetry, TLS metadata/fingerprinting (JA3/JA4), and behavioral anomaly modeling.

---

## 🚀 Key Capabilities (Target Architecture)

- **Passive & Non-Intrusive:** Works transparently on SPAN/TAP ports or PCAP files without altering network traffic or violating user privacy.
- **Threat Detection Coverage:**
  1. **DDoS & Amplification Attacks:** Volumetric floods (SYN, UDP, ICMP), DNS reflection.
  2. **Port & Network Scans:** Horizontal sweeps, vertical port scans, stealth SYN scans.
  3. **Command & Control (C2) Beaconing:** Periodic connection intervals, jitter analysis, heartbeat size uniformity.
  4. **DNS Tunneling & DGA:** Domain Shannon entropy, n-gram anomalies, query frequency, high-volume TXT lookups.
  5. **Suspicious Encrypted Flows:** TLS fingerprinting (JA3/JA4), packet sequence lengths, duration/byte asymmetries.
  6. **Data Exfiltration:** Asymmetric flow volume, unusual outbound burst patterns, anomalous off-hour transfers.
  7. **Behavioral Anomaly Detection:** Statistical deviations from learned baseline profiles.
- **Explainable Alerts & Risk Scoring:** MITRE ATT&CK framework mapping, feature-attribution evidence, confidence scoring, and multi-factor risk weighting.
- **Real-Time SOC Dashboard:** Live alert feed, flow inspector, threat distribution radar, and latency/throughput telemetry.
- **GenAI Security Analyst:** Specialized LLM agent acting strictly as an investigative advisor (incident summaries, query explanation, remediation playbooks) without serving as the primary threat classifier.
- **Rigorous Telemetry:** Native tracking of packet ingestion throughput (`packets/sec`), flow processing throughput (`flows/sec`), and end-to-end detection latency (`ms`).

---

## 📂 Repository Topology

The repository is organized as a modular monorepo cleanly separating shared domain models, ingestion, flow sessionization, feature engineering, threat detection, advisory GenAI, and user-facing applications:

```
sentinel-ai/
├── apps/
│   ├── api/                  # FastAPI backend (REST & WebSockets for SOC telemetry)
│   └── web/                  # React + Vite + TypeScript SOC Dashboard
├── packages/
│   ├── models/               # Pydantic domain contracts (Events, Flows, Alerts, Metrics)
│   ├── ingestion/            # Passive packet capture & raw header parsers
│   ├── flow_engine/          # Bi-directional 5-tuple flow aggregation & session tracking
│   ├── features/             # Statistical feature extraction (SPLT, entropy, timing)
│   ├── detection/            # Modular detection engine (Rules, Statistical, ML, Scoring)
│   └── ai_agent/             # Advisory GenAI Security Analyst (Triage & Playbooks)
├── data/
│   ├── samples/              # Sample PCAP captures for offline validation (.gitkeep)
│   └── synthetic/            # Synthetic test traffic generators (.gitkeep)
├── docs/
│   ├── architecture/         # System design, data pipeline & threat models
│   └── development/          # Roadmap, setup, and coding standards
├── tests/
│   ├── unit/                 # Unit tests for packages and core schemas
│   ├── integration/          # Pipeline integration tests
│   └── benchmarks/           # Throughput and latency benchmarking harnesses
├── docker-compose.yml        # Development environment orchestrator (minimal placeholder)
├── .env.example              # Documented environment variables template
└── ARCHITECTURE.md           # End-to-end architectural blueprint
```

---

## 🗺️ Implementation Roadmap (Phases 0 — 10)

SentinelAI is built systematically across 11 discrete phases:

- **Phase 0 — Architecture & Repository Foundation** *(Current)*
- **Phase 1 — Passive Traffic Ingestion & Flow Engine**
- **Phase 2 — Feature Engineering & Telemetry**
- **Phase 3 — Hybrid Threat Detection Engine**
- **Phase 4 — Alert Correlation, Evidence & Risk Scoring**
- **Phase 5 — FastAPI Backend & Persistence**
- **Phase 6 — Real-Time Streaming Architecture**
- **Phase 7 — React SOC Dashboard**
- **Phase 8 — GenAI Security Analyst**
- **Phase 9 — DevOps, Security & Cloud Deployment**
- **Phase 10 — Benchmarking, Hardening & SIH Demo**

See [ROADMAP.md](docs/development/ROADMAP.md) for full phase specifications, tasks, and acceptance criteria.

---

## 🛠️ Getting Started (Phase 0)

### Prerequisites
- Python 3.11+
- Node.js 20+ & npm (for web dashboard in Phase 7)
- Git

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/harshityad14/sentinel-ai.git
   cd sentinel-ai
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   ```

3. Install packages in editable mode:
   ```bash
   pip install -e packages/models
   pip install -e packages/ingestion
   pip install -e packages/flow_engine
   pip install -e packages/features
   pip install -e packages/detection
   pip install -e packages/ai_agent
   ```

4. Run unit sanity tests:
   ```bash
   python -m unittest discover -s tests/unit
   ```

---

## 📜 License & Compliance

Developed for **SIH 2026 Problem 145**.  
Strict adherence to passive network surveillance standards: no packet injection, no payload tampering, and no privacy-violating decryption.

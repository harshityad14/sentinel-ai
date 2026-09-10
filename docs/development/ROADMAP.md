# SentinelAI — Implementation Roadmap (Phases 0 — 10)

This roadmap defines the complete, phased engineering plan for building **SentinelAI** from architectural inception to a fully hardened, SIH 2026-ready passive network threat detection platform.

---

## Roadmap Overview

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8 ──► Phase 9 ──► Phase 10
 (Arch)     (Ingest)    (Features)   (Detect)     (Alerts)     (API/DB)   (Stream)     (React)     (GenAI)     (DevOps)     (Benchmark)
```

---

## Phase 0 — Architecture & Repository Foundation

- **Objective:** Establish a production-grade monorepo foundation, explicit architectural invariants, typed domain contracts, and comprehensive engineering documentation without premature dependencies.
- **Major Components:**
  - Repository structure (`apps/`, `packages/`, `docs/`, `tests/`, `data/`).
  - Core domain models package (`packages/models`).
  - Package interface stubs (`ingestion`, `flow_engine`, `features`, `detection`, `ai_agent`).
  - Minimal development orchestrator (`docker-compose.yml`, `.env.example`).
  - Architecture specifications, threat models, and coding standards.
- **Implementation Tasks:**
  - Define directory hierarchy and root configuration files.
  - Implement Pydantic domain models for `PacketMetadata`, `FlowRecord`, `Alert`, and `TelemetryMetrics`.
  - Author comprehensive architectural specifications including passive-security invariants.
  - Set up unit test scaffolding.
- **Tests:**
  - `tests/unit/test_models.py`: Validate Pydantic schema instantiation, field validation, and JSON serialization.
  - `tests/unit/test_packages_import.py`: Verify that all modular packages import cleanly without circular dependencies.
- **Acceptance Criteria:**
  - Zero syntax or import errors across all packages.
  - Passive-security invariant explicitly documented across architecture, standards, and contributing docs.
  - Clean `git status` with proper exclusions in `.gitignore`.
- **Dependencies on Previous Phases:** None (Initial Foundation).
- **Expected Deliverables:**
  - Fully initialized monorepo with `README.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `.gitignore`, `.env.example`, `docker-compose.yml`.
  - Documentation suite in `docs/architecture/` and `docs/development/`.
  - Validated `sentinel_models` package.

---

## Phase 1 — Passive Traffic Ingestion & Flow Engine

- **Objective:** Ingest raw network traffic passively (from PCAP files or live SPAN/TAP interfaces), extract protocol header metadata without payload inspection, and aggregate packets into stateful bi-directional 5-tuple flows.
- **Major Components:**
  - `packages/ingestion`: PCAP stream reader, live socket listener (read-only), protocol metadata parsers (Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, TLS).
  - `packages/flow_engine`: 5-tuple flow aggregator, sliding-window flow cache, active/inactive timeout managers, TCP connection state tracker.
- **Implementation Tasks:**
  - Implement PCAP reader supporting standard `.pcap` / `.pcapng` formats.
  - Implement passive live sniffer using raw sockets or `scapy`/`dpkt`/`pyshark` in read-only mode.
  - Parse L3/L4 headers, DNS query/answer metadata, and TLS ClientHello/ServerHello (SNI, cipher suites, JA3/JA4 fingerprints).
  - Implement bi-directional flow key normalization: `hash(min(src, dst), max(src, dst), ports, proto)`.
  - Implement flow expiration logic based on active/inactive timeouts and TCP FIN/RST flags.
- **Tests:**
  - Unit tests verifying correct 5-tuple flow key generation regardless of packet direction.
  - Unit tests for TCP state tracking (SYN -> SYN-ACK -> ACK -> FIN).
  - Replay test using sample PCAPs (benign traffic) validating that flow record counts match Wireshark baseline.
- **Acceptance Criteria:**
  - Ingestion runs strictly read-only with zero packet injection.
  - High-throughput PCAP ingestion without dropping packets on standard benchmark traces.
  - Emitted `FlowRecord` objects contain accurate packet counts, byte counts, duration, and protocol states.
- **Dependencies on Previous Phases:** Phase 0 (`sentinel_models`).
- **Expected Deliverables:**
  - Functional `packages/ingestion` and `packages/flow_engine`.
  - Integration test suite with sample PCAP fixtures in `data/samples/`.

---

## Phase 2 — Feature Engineering & Telemetry

- **Objective:** Extract statistical, temporal, and behavioral feature vectors from flow records and packet streams, and implement the platform telemetry subsystem to track throughput and latency.
- **Major Components:**
  - `packages/features`: SPLT extractor, inter-arrival jitter calculator, Shannon entropy calculator, byte/packet asymmetry ratios, DNS query analytics.
  - Telemetry instrumentation: Packet throughput counter (`packets/sec`), flow throughput counter (`flows/sec`), and pipeline latency tracker.
- **Implementation Tasks:**
  - Implement Sequence of Packet Lengths and Times (SPLT) feature representation for the first $N$ packets of each flow.
  - Implement statistical calculations: mean, variance, standard deviation, and autocorrelation of packet inter-arrival times.
  - Implement Shannon entropy functions for DNS domain names (for DGA detection) and byte frequency distributions.
  - Implement directional asymmetry ratios: $\frac{\text{bytes\_out}}{\text{bytes\_in}}$ and $\frac{\text{pkts\_out}}{\text{pkts\_in}}$.
  - Instrument pipeline stages with timestamp telemetry to measure end-to-end processing latency.
- **Tests:**
  - Mathematical unit tests for entropy calculation against known strings.
  - Unit tests for SPLT feature vectors across synthetic packet sequences.
  - Benchmarking test measuring feature extraction overhead (must process $> 10,000$ flows/sec).
- **Acceptance Criteria:**
  - Feature extraction completes in $< 100\,\mu\text{s}$ per flow.
  - Entropy calculations reliably distinguish random DGA strings from standard top-1000 domains.
  - Telemetry accurately records and logs throughput and latency metrics.
- **Dependencies on Previous Phases:** Phase 1 (`packages/ingestion`, `packages/flow_engine`).
- **Expected Deliverables:**
  - Production-ready `packages/features`.
  - Telemetry logging and metric collection utilities.

---

## Phase 3 — Hybrid Threat Detection Engine

- **Objective:** Implement modular, independently testable threat detection modules combining deterministic rule engines, statistical/anomaly profilers, and lightweight supervised machine learning models.
- **Major Components:**
  - `packages/detection/rules`: Volumetric DDoS detectors, port scan analyzers (horizontal, vertical, SYN stealth).
  - `packages/detection/statistical`: C2 beaconing analyzer (jitter/periodicity), DNS DGA & tunneling detector, baseline deviation profiler.
  - `packages/detection/ml`: Supervised classifier for suspicious encrypted traffic (JA3/JA4 + SPLT features).
- **Implementation Tasks:**
  - Implement Port Scan detector using failed TCP connection tracking and destination port entropy.
  - Implement DDoS detector evaluating packet volume surges and SYN-to-ACK imbalances.
  - Implement C2 Beaconing detector using FFT or autocorrelation on flow inter-arrival times.
  - Implement DNS Tunneling detector analyzing query lengths, subdomain depth, and TXT record volume.
  - Implement Encrypted Flow classifier using pre-trained tabular models (e.g., Random Forest or XGBoost).
  - Ensure all detectors output standardized partial detection signals.
- **Tests:**
  - Unit tests for each detector against synthetic attack patterns (simulated port scan, simulated beaconing, DGA queries).
  - False-positive testing against benign traffic traces.
- **Acceptance Criteria:**
  - Zero dependencies between individual detection modules (all can run in isolation).
  - Port scan detection triggers within $< 5$ seconds of scan initiation on synthetic traces.
  - C2 beaconing detector flags periodic heartbeats with $< 15\%$ jitter.
  - Zero payload decryption used across all detectors.
- **Dependencies on Previous Phases:** Phase 2 (`packages/features`, `packages/models`).
- **Expected Deliverables:**
  - Fully implemented `packages/detection` modules (Rules, Statistical, ML).
  - Test suites with attack simulation fixtures in `data/synthetic/`.

---

## Phase 4 — Alert Correlation, Evidence & Risk Scoring

- **Objective:** Aggregate multi-detector signals, correlate related events into unified threat incidents, generate explainable evidence chains with MITRE ATT&CK mapping, and compute composite risk scores.
- **Major Components:**
  - `packages/detection/correlation`: Time-window event correlator, duplicate alert deduplicator, attack chain linker.
  - `packages/detection/scoring`: Multi-factor risk scoring engine (0 — 100).
  - Evidence synthesis & MITRE ATT&CK catalog mapping.
- **Implementation Tasks:**
  - Implement alert deduplication to prevent alert storms during active floods.
  - Correlate multi-stage behaviors (e.g., Port Scan -> C2 Connection -> High Outbound Volume).
  - Map each alert to standard MITRE ATT&CK tactics, techniques, and sub-techniques.
  - Build composite risk scoring formula combining detection confidence, severity, target asset criticality, and attack persistence.
  - Generate structured explainability metadata detailing exact feature triggers for SOC analysts.
- **Tests:**
  - Unit tests verifying alert deduplication reduces alert volume by $\ge 80\%$ during sustained attacks.
  - Unit tests validating risk score bounds ($0 \le \text{score} \le 100$).
  - Validation of MITRE ATT&CK tagging correctness.
- **Acceptance Criteria:**
  - Alerts contain human-readable reasoning, raw feature evidence, and MITRE mapping.
  - Correlated incidents link related multi-host attacks into single actionable cases.
- **Dependencies on Previous Phases:** Phase 3 (`packages/detection`).
- **Expected Deliverables:**
  - Correlation and risk scoring engine in `packages/detection/correlation` and `packages/detection/scoring`.
  - Normalized `Alert` schema generator with explainability payloads.

---

## Phase 5 — FastAPI Backend & Persistence

- **Objective:** Build a high-performance REST and WebSocket API backend to serve real-time alerts, flow telemetry, system health, and threat statistics to the SOC dashboard.
- **Major Components:**
  - `apps/api`: FastAPI application, CORS middleware, API routing (`/api/v1`).
  - Persistence Layer: Relational / Time-series store (PostgreSQL / SQLite for local dev) storing alerts, asset profiles, and flow telemetry.
  - WebSocket hub for live event streaming to connected clients.
- **Implementation Tasks:**
  - Set up FastAPI app structure with dependency injection and settings management.
  - Implement REST endpoints:
    - `GET /api/v1/alerts`: Paginated alerts with filtering by severity, category, and time range.
    - `GET /api/v1/alerts/{id}`: Detailed alert view with evidence and explainability.
    - `GET /api/v1/telemetry`: Real-time throughput (`pkts/sec`, `flows/sec`) and latency metrics.
    - `GET /api/v1/health`: System health and status.
  - Implement WebSocket endpoint `/ws/alerts` for push-based alert delivery.
  - Implement database models and migrations for alert persistence.
- **Tests:**
  - API endpoint integration tests using `httpx.AsyncClient`.
  - WebSocket connection and broadcast test.
  - Database CRUD tests for alerts and telemetry records.
- **Acceptance Criteria:**
  - REST endpoints respond with $< 50\,\text{ms}$ latency for standard queries.
  - WebSocket clients receive new alerts within $< 20\,\text{ms}$ of generation.
  - Full OpenAPI/Swagger documentation auto-generated at `/docs`.
- **Dependencies on Previous Phases:** Phase 4 (`packages/models`, `packages/detection`).
- **Expected Deliverables:**
  - Production-ready `apps/api` service.
  - Database schema and migration scripts.

---

## Phase 6 — Real-Time Streaming Architecture

- **Objective:** Introduce Apache Kafka as the distributed, decoupled streaming backbone to support horizontal scaling, resilient message buffering, and high-throughput production workloads.
- **Major Components:**
  - Kafka cluster orchestration (Kafka + Zookeeper / KRaft).
  - Producers: Ingestion packet producer, flow engine producer.
  - Consumers: Detection engine consumer groups, persistence consumers.
  - In-memory fallback mode for standalone local development without Kafka.
- **Implementation Tasks:**
  - Define topic schemas: `sentinel.packets.raw`, `sentinel.flows.aggregated`, `sentinel.alerts.high`.
  - Implement resilient Kafka producers with batching and compression.
  - Implement consumer worker groups for parallelized threat detection.
  - Maintain an abstraction layer allowing the pipeline to toggle between in-process queues and Kafka.
  - Update `docker-compose.yml` to include Kafka/KRaft service profile.
- **Tests:**
  - Integration test verifying message delivery across producer -> Kafka -> consumer.
  - Fault tolerance test: consumer restart and lag catch-up without message loss.
- **Acceptance Criteria:**
  - Sustained streaming throughput of $> 25,000$ messages/sec over Kafka.
  - Pipeline operates seamlessly in both standalone (in-memory) and distributed (Kafka) modes.
- **Dependencies on Previous Phases:** Phase 1 — Phase 5.
- **Expected Deliverables:**
  - Kafka integration modules and configuration profiles.
  - Updated multi-service `docker-compose.yml`.

---

## Phase 7 — React SOC Dashboard

- **Objective:** Create a modern, high-performance, real-time Security Operations Center (SOC) dashboard using React, Vite, and TypeScript to visualize network telemetry, inspect flows, and triage alerts.
- **Major Components:**
  - `apps/web`: React + Vite + TypeScript application.
  - Real-time Alert Feed: Live WebSocket-driven alert table with instant severity badges.
  - Threat Radar & Statistics: Attack category distribution, top targeted IPs, active scans.
  - Flow Inspector: Searchable, filterable view of recent network flows and session metadata.
  - Incident Detail Drawer: In-depth view of alert evidence, MITRE ATT&CK tactics, and feature values.
- **Implementation Tasks:**
  - Set up React 18 + Vite + TypeScript project structure.
  - Implement WebSocket client hook with auto-reconnect and state synchronization.
  - Build responsive dark-mode SOC UI with accessible, high-contrast threat color schemes.
  - Implement interactive time-series charts for throughput and packet volume telemetry.
  - Build incident detail view showing feature attribution and raw metadata evidence.
- **Tests:**
  - Component unit tests with React Testing Library / Vitest.
  - WebSocket mock tests verifying UI updates upon incoming alert messages.
- **Acceptance Criteria:**
  - Dashboard renders incoming alerts in real-time with $< 50\,\text{ms}$ UI render latency.
  - Clean, responsive UI with zero console errors or hydration warnings.
  - Fully typed data interfaces synchronized with `packages/models`.
- **Dependencies on Previous Phases:** Phase 5 (`apps/api` REST & WebSocket endpoints).
- **Expected Deliverables:**
  - Complete `apps/web` frontend application with production build configuration.

---

## Phase 8 — GenAI Security Analyst

- **Objective:** Deploy an advisory LLM-powered Security Analyst agent that ingests detection evidence, generates contextual natural-language incident reports, explains attack mechanics, and proposes remediation playbooks.
- **Major Components:**
  - `packages/ai_agent`: Prompt management, LLM provider integration (OpenAI/Anthropic/Local LLM), structured output parser.
  - API endpoints for on-demand alert investigation and playbook synthesis.
  - Frontend AI Analyst drawer in the SOC dashboard.
- **Implementation Tasks:**
  - Enforce architectural boundary: **The LLM is strictly advisory and NEVER acts as the primary threat classifier**.
  - Implement prompt templates ingesting structured alert evidence (features, MITRE technique, host context).
  - Generate 3 key outputs per investigated alert:
    1. **Executive Incident Summary:** Clear explanation of what happened and potential impact.
    2. **Technical Deep-Dive:** Analysis of why the detection fired and specific indicators.
    3. **Recommended Remediation Playbook:** Advisory containment steps (e.g., firewall rule syntax, host isolation advice).
  - Implement response caching to minimize redundant LLM token costs.
- **Tests:**
  - Unit tests verifying structured JSON parsing of LLM outputs.
  - Mocked provider tests validating prompt assembly and fallback behavior on API timeout.
- **Acceptance Criteria:**
  - Generated summaries are grounded strictly in the provided alert evidence (zero hallucinated IP addresses or ports).
  - Graceful degradation when LLM API keys are unconfigured or rate-limited.
- **Dependencies on Previous Phases:** Phase 4 (`Alert` schema with evidence), Phase 5 (API), Phase 7 (Dashboard UI).
- **Expected Deliverables:**
  - `packages/ai_agent` module with prompt pipelines and test suites.
  - API endpoint `POST /api/v1/alerts/{id}/investigate` and frontend UI integration.

---

## Phase 9 — DevOps, Security & Cloud Deployment

- **Objective:** Package SentinelAI for automated continuous integration, secure containerized execution, and production cloud deployment.
- **Major Components:**
  - Multi-stage Dockerfiles for API, Web, and worker nodes.
  - Production `docker-compose.prod.yml` and Kubernetes manifests / Helm charts.
  - GitHub Actions CI/CD workflows for linting, type-checking, automated testing, and security scanning.
  - TLS encryption for API/WebSocket endpoints and role-based access control (RBAC).
- **Implementation Tasks:**
  - Optimize Dockerfiles using multi-stage builds and non-root users.
  - Build CI workflow `.github/workflows/ci.yml` running unit tests, linting, and security audits (`bandit`, `pip-audit`).
  - Configure environment secret management and production logging.
  - Implement rate-limiting and basic authentication on API endpoints.
- **Tests:**
  - Docker container build and startup healthcheck tests.
  - End-to-end CI pipeline execution on pull requests.
- **Acceptance Criteria:**
  - Production containers build with zero critical vulnerability findings.
  - Automated CI tests pass with $100\%$ green status.
  - Complete deployment documentation for single-node Docker and cloud environments.
- **Dependencies on Previous Phases:** Phase 1 — Phase 8.
- **Expected Deliverables:**
  - Production Dockerfiles, CI/CD pipeline definitions, and deployment guides.

---

## Phase 10 — Benchmarking, Hardening & SIH Demo

- **Objective:** Subject SentinelAI to comprehensive performance benchmarking, stress-test high-volume attack traffic, harden detection accuracy, and prepare demonstration scripts for SIH 2026.
- **Major Components:**
  - Benchmarking harness measuring:
    1. **Packet Ingestion Throughput (`packets/sec`)**
    2. **Flow Processing Throughput (`flows/sec`)**
    3. **End-to-End Detection Latency (`ms`)**
  - SIH demonstration kit: attack generator scripts, pre-recorded PCAP scenarios, live demo orchestrator.
  - Final documentation and executive slide deck.
- **Implementation Tasks:**
  - Build automated benchmark test suite running against standard datasets (e.g., CIC-IDS2017, CTU-13, custom PCAPs).
  - Measure and record baseline metrics:
    - Packet ingestion throughput target: $\ge 50,000\,\text{pkts/sec}$ offline.
    - Flow processing throughput target: $\ge 5,000\,\text{flows/sec}$.
    - Detection latency target: $< 100\,\text{ms}$ for rule/statistical detection.
  - Fine-tune detection thresholds to optimize precision and recall (target $F_1 \ge 0.95$).
  - Create one-command live demonstration script showcasing automated detection of DDoS, Port Scan, C2 Beaconing, and DNS Tunneling with real-time SOC dashboard alerts and GenAI investigation.
- **Tests:**
  - Full end-to-end regression test suite across all 7 threat categories.
  - Stress test under sustained high-load traffic.
- **Acceptance Criteria:**
  - All 3 benchmark metrics meet or exceed defined targets.
  - Demo script successfully executes end-to-end detection and alert visualization in under 3 minutes.
  - Flawless presentation package ready for SIH 2026 evaluation.
- **Dependencies on Previous Phases:** All previous phases (Phase 0 — Phase 9).
- **Expected Deliverables:**
  - Benchmark harness and published performance report.
  - Demo orchestration scripts in `scripts/demo/`.
  - Final project documentation and evaluation presentation.

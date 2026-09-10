# SentinelAI — Implementation Roadmap (Phases 0 — 10)

This roadmap defines the complete, phased engineering plan for building **SentinelAI** from architectural inception to a fully hardened, SIH 2026-ready passive network threat detection platform.

---

## Roadmap Overview

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8 ──► Phase 9 ──► Phase 10
 (Arch)     (Ingest)    (Features)   (Detect)     (Alerts)     (API/DB)   (Stream)     (React)     (GenAI)     (DevOps)     (Benchmark)
```

---

## Phase 0 — Architecture & Repository Foundation ✅ [COMPLETED]

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

## Phase 1 — Passive Traffic Ingestion & Flow Engine ✅ [COMPLETED]

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

## Phase 2 — Feature Engineering & Telemetry ✅ [COMPLETED]

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

## Phase 3 — Hybrid Threat Detection Engine ✅ [COMPLETED]

- **Objective:** Implement modular, independently testable threat detection modules combining deterministic rule engines, statistical/anomaly profilers, lightweight supervised machine learning models, and an ensemble correlation layer.
- **Major Components:**
  - `packages/detection/rules`: 8 deterministic rule detectors (`syn_flood`, `udp_flood`, `port_scan`, `c2_beaconing`, `dns_dga`, `dns_tunneling`, `data_exfiltration`, `suspicious_tls`).
  - `packages/detection/statistical`: Z-score behavioral anomaly profiler (`anomaly_detector.py`) with dynamic baseline updating.
  - `packages/detection/ml`: Decoupled supervised Random Forest classifier with strict feature ordering, missing-feature imputation, and deterministic baseline fixture (`random_forest_detector.py`, `trainer.py`, `model_metadata.py`).
  - `packages/detection/correlation`: Weighted multi-detector ensemble correlation engine (`ensemble.py`) with multi-detector agreement bonus.
  - `packages/detection/scoring`: Domain-based severity policy separating confidence from severity (`severity_policy.py`).
  - `packages/detection/pipeline.py`: Unified `DetectionPipeline` orchestrating all active detectors.
- **Implementation Tasks:**
  - [x] Strongly-typed domain models (`ThreatType`, `DetectorType`, `DetectionSeverity`, `DetectionEvidence`, `DetectionSignal`, `DetectionResult`).
  - [x] `BaseDetector` abstract interface with modular isolation.
  - [x] 8 deterministic rule detectors with configurable thresholds.
  - [x] Host-context-aware Port Scan detector consuming multi-flow fan-out correlation.
  - [x] Statistical anomaly detector with robust Z-score profiling against configurable baselines.
  - [x] Supervised ML inference infrastructure with metadata validation, explainable feature contributions, and offline trainer separation.
  - [x] Ensemble correlation engine with weighted confidence fusion and agreement bonus.
  - [x] Explainable machine-readable evidence referencing actual flow features.
  - [x] Comprehensive deterministic test suite across all 10 threat scenarios.
  - [x] Performance benchmark measuring throughput and latency across detector categories.
- **Tests:**
  - `tests/unit/test_detection.py`: 43 deterministic unit tests covering obvious positives, normal traffic, borderline cases, missing metadata, and invalid inputs.
  - `tests/benchmarks/benchmark_detection.py`: Performance benchmark measuring flows/sec and latency per detector class.
- **Acceptance Criteria:**
  - [x] Zero network sockets, packet transmissions, active probing, or payload decryption.
  - [x] Confidence mathematically separated from Severity.
  - [x] Port scan detector requires correlated multi-port evidence.
  - [x] Individual contributing signals preserved within `DetectionResult.signals`.
  - [x] Rule engine throughput $> 40,000$ flows/sec; Full hybrid pipeline $> 400$ flows/sec.
- **Dependencies on Previous Phases:** Phase 2 (`packages/features`, `packages/models`).
- **Expected Deliverables:**
  - Production-ready `packages/detection` package.
  - `docs/architecture/detection_engine.md` and `docs/architecture/threat_detection_matrix.md`.

---

## Phase 4 — Alert Correlation, Evidence & Risk Scoring ✅ [COMPLETED]

- **Objective:** Aggregate multi-detector signals, correlate related events into unified threat incidents, generate explainable evidence chains with MITRE ATT&CK mapping, and compute composite risk scores.
- **Major Components:**
  - `packages/detection/correlation`: Time-window event correlator (`correlator.py`), configuration dataclass (`config.py`), static MITRE ATT&CK mapper (`mitre_mapper.py`).
  - `packages/detection/scoring`: Multi-factor risk scoring engine (`risk_calculator.py`).
  - Domain models: `SecurityAlert`, `AlertEvidence`, `AlertSignal`, `AlertEntity`, `RiskScore`, `CorrelationGroup` in `packages/models/sentinel_models/alerts.py`.
- **Implementation Tasks:**
  - [x] Implement alert deduplication to merge identical alerts and prevent alert storms.
  - [x] Correlate multi-stage behaviors (e.g., Port Scan -> C2 Connection -> High Outbound Volume).
  - [x] Map each alert to standard MITRE ATT&CK tactics, techniques, and sub-techniques.
  - [x] Build composite risk scoring formula combining detection confidence, severity, detector agreement, signal volume, recurrence, and temporal proximity.
  - [x] Generate structured explainability metadata detailing exact feature triggers for SOC analysts.
  - [x] Enforce bounded memory caps and sliding window pruning.
- **Tests:**
  - `tests/unit/test_alert_correlation.py`: 19 deterministic unit tests verifying deduplication, temporal correlation, entity grouping, risk calculation, evidence preservation, and lifecycle transitions.
  - `tests/benchmarks/benchmark_correlation.py`: Performance benchmark measuring detections/sec, alerts/sec, average and P99 latency.
- **Acceptance Criteria:**
  - [x] Alerts contain human-readable reasoning, raw feature evidence, and MITRE mapping.
  - [x] Correlated incidents link related multi-host attacks into single actionable cases.
  - [x] Deduplication reduces alert volume by $\ge 80\%$ during sustained repeated floods.
  - [x] Risk score bounded between $0$ and $100$ with transparent factor breakdown.
  - [x] Correlation throughput $> 8,000$ detections/sec; average latency $< 0.2$ ms.
- **Dependencies on Previous Phases:** Phase 3 (`packages/detection`).
- **Expected Deliverables:**
  - Correlation and risk scoring engine in `packages/detection/correlation` and `packages/detection/scoring`.
  - Canonical `SecurityAlert` domain model and `docs/architecture/alert_correlation.md`.

---

## Phase 5 — FastAPI Backend & Persistence ✅ [COMPLETED]

- **Objective:** Build a high-performance REST API backend and PostgreSQL / TimescaleDB-compatible persistence layer for SentinelAI with typed schemas, versioned migrations, and SOC query capabilities.
- **Major Components:**
  - `apps/api/app`: FastAPI application factory, lifespan context, CORS, structured exception handling.
  - `apps/api/app/db`: SQLAlchemy 2.0 engine, scoped sessions, connection health checks, SQLite / PostgreSQL portability.
  - `apps/api/app/models`: 10 relational ORM models (`flows`, `flow_features`, `detections`, `detection_evidence`, `security_alerts`, `alert_signals`, `alert_evidence`, `alert_entities`, `correlation_groups`, `alert_lifecycle_history`).
  - `apps/api/alembic`: Versioned migration system with deterministic upgrade/downgrade scripts (`001_initial_schema.py`).
  - `apps/api/app/repositories` & `apps/api/app/services`: Layered architecture enforcing SOC query abstraction and internal-only alert lifecycle state transitions.
  - `apps/api/app/api/v1`: Typed endpoint routing for flows, detections, alerts, statistics, and system readiness.
- **Implementation Tasks:**
  - [x] Build application factory and environment-based configuration.
  - [x] Implement database models and TimescaleDB-compatible table design.
  - [x] Add Alembic migration pipeline with reversible schema migrations.
  - [x] Implement repository and business service layer with zero raw SQL in route handlers.
  - [x] Expose paginated query APIs for flows, detections, alerts, and system statistics.
  - [x] Expose internal alert acknowledgement and resolution lifecycle endpoints.
  - [x] Enforce passive security invariant (zero packet injection, active probing, or firewall changes).
- **Tests & Benchmarks:**
  - `tests/unit/test_api.py`: 17 deterministic tests for health, readiness, CRUD, transactions, lifecycle, filtering, pagination, and validation.
  - `tests/benchmarks/benchmark_backend.py`: Benchmarking query latency, detection throughput, and insertion throughput.
- **Acceptance Criteria:**
  - [x] All Phase 0–5 unit tests pass (126/126 tests).
  - [x] Clean repository/service separation.
  - [x] Actual measured query latency: Alert query ~23.9 ms, Flow query ~7.8 ms.
  - [x] Passive security verified with zero active network operations.
  - [x] Full OpenAPI/Swagger documentation auto-generated at `/docs`.
- **Dependencies on Previous Phases:** Phase 4 (`packages/models`, `packages/detection`).
- **Expected Deliverables:**
  - Production-ready `apps/api` service and persistence layer.
  - Database schema, Alembic migration scripts, and architecture docs.

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

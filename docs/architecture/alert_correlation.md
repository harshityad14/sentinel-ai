# SentinelAI — Alert Correlation, Evidence & Risk Scoring Architecture

## 1. Overview

Phase 4 introduces the **Alert Correlation, Evidence & Risk Scoring Engine** for SentinelAI. It transforms raw, high-velocity `DetectionResult` streams emitted by Phase 3 into structured, deduplicated, and prioritized `SecurityAlert` incidents.

```
                  Phase 3 DetectionResult Streams
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Alert Correlator    │
                    │   (Sliding Window)    │
                    └───────────┬───────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
1. Deduplication        2. Entity Grouping      3. Cross-Threat Linking
   (Cooldown/Merge)        (IP/Host/Subnet)        (Multi-Stage Chains)
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                    ┌───────────────────────┐
                    │ Multi-Factor Risk     │
                    │ Scoring Engine (0-100)│
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Offline MITRE ATT&CK  │
                    │ Static Catalog Mapper │
                    └───────────┬───────────┘
                                │
                                ▼
                    Canonical SecurityAlert
                    (JSON Serializable / Immutable)
```

---

## 2. Core Alert Domain Models

Defined in `sentinel_models.alerts`:

- **`SecurityAlert`**: The canonical alert entity containing complete incident context:
  - `alert_id`: Unique identifier (e.g. `alt_a1b2c3d4e5f6`).
  - `timestamp`, `first_seen`, `last_seen`: Temporal bounds of the security incident.
  - `flow_ids`: List of all associated network flow IDs aggregated into this alert.
  - `source_entity`, `destination_entity`: Structured `AlertEntity` records (IP, port, role).
  - `threat_class`: Specific threat classification (e.g. `SYN_FLOOD`, `PORT_SCAN`, `C2_BEACONING`).
  - `confidence`: Algorithmic detector certainty ($0.0 - 1.0$), preserved independently.
  - `severity`: Operational impact rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - `risk_score`: Prioritized multi-factor `RiskScore` ($0 - 100$) with explainability breakdown.
  - `evidence`: Consolidated machine-readable `AlertEvidence` referencing real telemetry features.
  - `contributing_signals`: Individual preserved `AlertSignal` records from specialized detectors.
  - `correlation_group_id`: Identifier linking multi-stage incidents across the same entity.
  - `status`: Lifecycle state (`NEW`, `ACTIVE`, `ACKNOWLEDGED`, `RESOLVED`).
  - `mitre_attack`: Static `MitreAttackRef` detailing tactic, technique, and sub-technique.

---

## 3. Correlation & Deduplication Strategy

Implemented in `sentinel_detection.correlation.AlertCorrelator`:

### 3.1 Sliding Time Window
Maintains bounded in-memory sliding windows (default `time_window_sec = 60.0s`). Events occurring outside this active window are automatically pruned via `prune_expired()`.

### 3.2 Deduplication & Aggregation
Identical repeated detections (same source IP + threat type) within `duplicate_window_sec` (default $20.0 - 30.0\text{s}$) are merged into the existing active alert rather than emitting alert floods:
- `last_seen` timestamp is updated.
- Distinct network `flow_id` references are appended.
- Contributing detector signals and non-duplicate evidence are preserved.
- Alert status transitions from `NEW` to `ACTIVE`.
- Risk score is dynamically recalculated to reflect increased volume and recurrence.

### 3.3 Cross-Threat & Entity Aggregation
When a single host initiates sequential attack stages (e.g., `PORT_SCAN` reconnaissance followed by `C2_BEACONING` outbound command and control), the correlator links both alerts into a unified `CorrelationGroup` via `entity_group_index`.

---

## 4. Multi-Factor Risk Scoring Formula

Implemented in `sentinel_detection.scoring.RiskCalculator`:

The risk score is a deterministic, bounded value ($0 \le \text{Score} \le 100$) derived from six weighted components:

$$\text{RiskScore} = \text{round}\left( \text{clamp}\left( 100 \times \sum_{i} w_i \cdot F_i, \, 0, \, 100 \right) \right)$$

Where factors $F_i \in [0.0, 1.0]$ are:

1. **Confidence Factor ($F_{\text{conf}}$)**: Raw algorithmic detector certainty ($0.0 - 1.0$). Weight: $0.25$.
2. **Severity Factor ($F_{\text{sev}}$)**: Operational impact weight (LOW: $0.25$, MEDIUM: $0.50$, HIGH: $0.75$, CRITICAL: $1.00$). Weight: $0.30$.
3. **Agreement Factor ($F_{\text{agree}}$)**: Boost based on distinct detector categories agreeing on the threat (1 category: $0.40$, 2 categories: $0.75$, 3+ categories: $1.00$). Weight: $0.15$.
4. **Signal Count Factor ($F_{\text{signals}}$)**: Volume saturation curve $1 - e^{-0.20 \cdot (n - 1)}$. Weight: $0.10$.
5. **Recurrence Factor ($F_{\text{recurrence}}$)**: Repetition frequency across the observation window $\min(1.0, \frac{r - 1}{10})$. Weight: $0.10$.
6. **Temporal Proximity Factor ($F_{\text{temporal}}$)**: Burst density factor $1 - \frac{\Delta t}{W}$. Weight: $0.10$.

Every `RiskScore` exposes a `breakdown` dictionary detailing the exact point contributions for SOC dashboard and GenAI explanation.

---

## 5. Offline MITRE ATT&CK Mapping

Implemented in `sentinel_detection.correlation.MitreAttackMapper`:

A static, local, offline catalog mapping threat types to standardized MITRE ATT&CK IDs:

| Threat Class | MITRE Tactic | Tactic ID | MITRE Technique | Technique ID |
| :--- | :--- | :--- | :--- | :--- |
| `SYN_FLOOD` | Impact | TA0040 | Network Denial of Service | T1498.001 |
| `UDP_FLOOD` | Impact | TA0040 | Network Denial of Service | T1498.001 |
| `PORT_SCAN` | Discovery | TA0007 | Network Service Discovery | T1046 |
| `C2_BEACONING` | Command and Control | TA0011 | Application Layer Protocol | T1071.001 |
| `DNS_DGA` | Command and Control | TA0011 | Dynamic Resolution | T1568.002 |
| `DNS_TUNNELING` | Exfiltration | TA0010 | Application Layer Protocol | T1071.004 |
| `SUSPICIOUS_TLS` | Command and Control | TA0011 | Encrypted Channel | T1573.002 |
| `DATA_EXFILTRATION` | Exfiltration | TA0010 | Exfiltration Over Alternative Protocol | T1048.003 |
| `BEHAVIORAL_ANOMALY` | Defense Evasion | TA0005 | Application Layer Protocol | T1071 |

> [!NOTE]
> The MITRE catalog is purely a static enrichment utility. It performs zero external network requests and does not influence core detection logic.

---

## 6. Passive Security & Operational Invariants

1. **Zero Socket / Network Communication**: The correlation and scoring engine operates purely in-memory on incoming detection data.
2. **Internal Lifecycle Only**: Alert state transitions (`NEW` $\to$ `ACTIVE` $\to$ `ACKNOWLEDGED` $\to$ `RESOLVED`) are strictly internal data model modifications. No packet filtering, firewall reconfiguration, or active host isolation is executed.
3. **Bounded Memory**: Enforces configurable capacity caps (`max_signals_per_alert`, `max_active_alerts`, `max_active_groups`) to guarantee predictable memory consumption under sustained flood conditions.

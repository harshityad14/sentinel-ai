# SentinelAI Backend & Persistence Architecture (Phase 5)

## 1. Overview

The **SentinelAI Backend & Persistence Layer** provides high-throughput telemetry storage, query APIs, and analyst lifecycle state management for the SentinelAI platform. It exposes a typed, RESTful HTTP interface (`/api/v1`) built on **FastAPI** backed by a **PostgreSQL / TimescaleDB-compatible** relational schema managed by **SQLAlchemy 2.0** and **Alembic**.

```
┌────────────────────────────────────────────────────────┐
│                   FastAPI Application                  │
│   (App Factory, Lifespan, CORS, Exception Handlers)    │
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
      Health / Readiness           API v1 Router
                                          │
            ┌───────────────┬─────────────┴─────────────┬──────────────┐
            ▼               ▼                           ▼              ▼
       /api/v1/flows  /api/v1/detections         /api/v1/alerts  /api/v1/statistics
            │               │                           │              │
            └───────────────┼───────────────────────────┼──────────────┘
                            ▼                           ▼
                 Services (Flow, Detection, Alert, Stats)
                            │
                            ▼
              Repositories (FlowRepo, DetRepo, AlertRepo)
                            │
                            ▼
            SQLAlchemy 2.0 ORM & Connection Pool
                            │
                            ▼
         PostgreSQL / TimescaleDB (or SQLite for dev/test)
```

---

## 2. API Design & Routing

All operational endpoints are versioned under `/api/v1`:

| Method | Path | Description | Access |
|---|---|---|---|
| `GET` | `/health` | Root service health check | Public |
| `GET` | `/api/v1/health` | Timestamped liveness check | Public |
| `GET` | `/api/v1/readiness` | Database connectivity readiness probe | Infrastructure |
| `GET` | `/api/v1/status` | Ingestion status & passive monitoring confirmation | SOC / Ops |
| `GET` | `/api/v1/flows` | Paginated network flows with IP/protocol/time filters | Analyst / SOC |
| `GET` | `/api/v1/flows/{flow_id}` | Retrieve individual bidirectional flow record | Analyst / SOC |
| `GET` | `/api/v1/detections` | Paginated threat detections with evidence items | Analyst / SOC |
| `GET` | `/api/v1/detections/{detection_id}` | Detailed detection result & contributing features | Analyst / SOC |
| `GET` | `/api/v1/alerts` | Paginated alerts (threat class, severity, risk, status) | Analyst / SOC |
| `GET` | `/api/v1/alerts/{alert_id}` | Full alert with evidence, signals, entities, audit history | Analyst / SOC |
| `POST` | `/api/v1/alerts/{alert_id}/acknowledge` | Acknowledge alert (strictly internal state change) | Analyst / SOC |
| `POST` | `/api/v1/alerts/{alert_id}/resolve` | Resolve alert with notes (strictly internal state change) | Analyst / SOC |
| `GET` | `/api/v1/alerts/statistics` | Summary counts by status, severity, and threat class | Dashboard / SOC |
| `GET` | `/api/v1/statistics/threats` | Distribution breakdown of detected threat types | Dashboard / SOC |
| `GET` | `/api/v1/statistics/entities` | Top network entities (IPs, hosts) linked to incidents | Dashboard / SOC |
| `GET` | `/api/v1/statistics/summary` | Aggregated system telemetry overview | Dashboard / SOC |

---

## 3. Database Schema & TimescaleDB Compatibility

The database schema consists of 10 primary tables designed with clean foreign key cascades and composite indexes:

1. **`flows`**: Persisted bidirectional network flows (`flow_id`, `start_time`, `end_time`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_count`, `byte_count`, `packets_fwd`, `packets_bwd`, `bytes_fwd`, `bytes_bwd`, `is_bidirectional`, `metadata_json`).
   - *TimescaleDB Compatibility*: Partitionable by `start_time` as a hypertable.
2. **`flow_features`**: Extracted statistical and protocol feature vectors (`flow_id`, `timestamp`, `features`, `status`).
3. **`detections`**: Detector consensus decisions (`detection_id`, `flow_id`, `threat_type`, `severity`, `confidence`, `is_threat`, `detector_name`, `timestamp`).
4. **`detection_evidence`**: Feature-level triggering metrics and anomaly scores (`detection_id`, `feature_name`, `observed_value`, `threshold`, `score`, `contribution`, `description`).
5. **`correlation_groups`**: Threat clusters aggregated across entity and temporal windows (`group_id`, `primary_entity`, `threat_type`, `first_seen`, `last_seen`, `alert_count`, `signal_count`).
6. **`security_alerts`**: High-fidelity correlated incident alerts (`alert_id`, `correlation_group_id`, `threat_class`, `severity`, `status`, `confidence`, `risk_score`, `risk_level`, `risk_breakdown`, `mitre_attack`, `title`, `description`, `explanation`, `flow_ids`, `first_seen`, `last_seen`).
7. **`alert_signals`**: Contributing detection signals (`alert_id`, `detection_id`, `flow_id`, `threat_type`, `severity`, `confidence`, `detector_type`, `timestamp`).
8. **`alert_evidence`**: Corroborating machine-readable evidence items (`alert_id`, `signal_id`, `evidence_type`, `description`, `raw_values`, `confidence`, `weight`).
9. **`alert_entities`**: Involved network hosts, IPs, or domains (`alert_id`, `entity_type`, `identifier`, `role`, `confidence`).
10. **`alert_lifecycle_history`**: Immutable SOC analyst audit trail (`alert_id`, `previous_status`, `new_status`, `changed_at`, `changed_by`, `notes`).

---

## 4. Database Migrations (Alembic)

Deterministic schema versioning is managed with Alembic:
- Configuration: `apps/api/alembic.ini`
- Environment runner: `apps/api/alembic/env.py`
- Initial schema: `apps/api/alembic/versions/001_initial_schema.py`

### Running Migrations

```bash
# Upgrade to latest migration
python -m alembic -c apps/api/alembic.ini upgrade head

# Revert migration
python -m alembic -c apps/api/alembic.ini downgrade base
```

---

## 5. Configuration & Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./sentinel.db` | Connection URI (SQLite for local dev/test, PostgreSQL for production) |
| `SENTINEL_ENV` | `development` | Deployment environment: `development`, `test`, `production` |
| `API_HOST` | `0.0.0.0` | Binding interface |
| `API_PORT` | `8000` | Binding port |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `DB_POOL_SIZE` | `10` | SQLAlchemy connection pool size (PostgreSQL) |
| `DB_MAX_OVERFLOW` | `20` | Max overflow pool connections |
| `DEFAULT_PAGE_LIMIT` | `50` | Default query page size |
| `MAX_PAGE_LIMIT` | `500` | Maximum allowable page size |

---

## 6. Passive Security Invariant Verification

SentinelAI enforces a strict passive security guarantee:
- **No Packet Injection**: Zero raw socket transmission or packet generation in the backend.
- **No Active Probing**: Detection and scoring rely entirely on passively ingested traffic.
- **No Firewall Modification**: Alert acknowledgement and resolution modify ONLY internal application/database records.
- **No Payload Decryption**: Only cleartext headers, unencrypted TLS handshakes (SNI, JA3), and flow telemetry are stored.

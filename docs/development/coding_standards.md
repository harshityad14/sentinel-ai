# SentinelAI — Coding Standards & Engineering Guidelines

## 1. Foundational Security Invariant

Every developer contributing to SentinelAI must internalize and adhere to our foundational invariant:

> **"The SentinelAI detection pipeline is strictly passive. No component may transmit packets, perform active probing, complete network handshakes, block traffic, or decrypt application payloads."**

### Invariant Enforcement Rules:
1. **Zero Egress / Outbound Transmission:**
   - No code may invoke `socket.send()`, `socket.sendto()`, `scapy.send()`, `scapy.sr()`, `scapy.sr1()`, or equivalent networking APIs that emit packets onto monitored network segments.
   - Any proposed PR containing packet generation or transmission logic will be rejected.
2. **Zero Active Scanning / Handshakes:**
   - No component may initiate TCP handshakes, ICMP pings, or DNS resolutions targeting observed external IP addresses.
3. **Zero Payload Decryption:**
   - Payloads encrypted via TLS/SSL, SSH, or VPN protocols must remain opaque.
   - Analysis must rely exclusively on connection metadata, handshake attributes (SNI, cipher suites, extensions, JA3/JA4), packet length sequences (SPLT), and inter-packet arrival times.
4. **Advisory Mitigation Only:**
   - SentinelAI generates alerts and proposed remediation playbooks. It does not act as an in-line firewall or active IPS.

---

## 2. Python Engineering Standards

### 2.1 Typing & Validation
- **Strict Typing:** All function signatures and class methods must include complete Python type hints (`typing` module / Python 3.10+ native types).
- **Data Models:** All domain entities, events, alerts, and configurations must be modeled using **Pydantic V2** (`BaseModel`).
- **No Untyped Dictionaries:** Avoid passing arbitrary dictionaries (`dict[str, Any]`) across module boundaries. Use typed Pydantic models.

### 2.2 Code Formatting & Linting
- **Formatter:** `black` (line length: 100).
- **Linter:** `ruff` with standard rules enabled (`E`, `F`, `W`, `C90`, `I`, `N`).
- **Type Checker:** `mypy` in strict or standard checking mode.

### 2.3 Exception Handling & Logging
- Use standard `logging` with structured formatting (e.g. `logger = logging.getLogger(__name__)`).
- Never use bare `except:` clauses. Always catch specific exceptions (`ValueError`, `KeyError`, `OSError`).
- Log diagnostic messages at `DEBUG` or `INFO` levels. Use `WARNING` and `ERROR` strictly for exceptional failure conditions.

---

## 3. Package Separation & Architecture Integrity

SentinelAI enforces strict boundaries between packages:

1. **`sentinel_models`:** The single source of truth for schemas. Other packages depend on `sentinel_models`, but `sentinel_models` must never depend on other internal packages.
2. **`sentinel_ingestion`:** Responsible only for packet acquisition and raw parsing. It does not compute flow aggregations or execute detection rules.
3. **`sentinel_flow_engine`:** Responsible only for stateful flow grouping and session management.
4. **`sentinel_features`:** Responsible for transforming raw flows into statistical feature representations.
5. **`sentinel_detection`:** Independent detection modules (rules, statistical, ML, correlation, scoring). Modules must be independently unit-testable.
6. **`sentinel_ai_agent`:** Advisory assistant. **Must never be the authoritative threat classifier.**

---

## 4. Frontend Standards (Phase 7)

- **Language:** TypeScript with strict mode enabled (`noImplicitAny: true`).
- **Framework:** React 18+ with functional components and hooks.
- **Styling:** Modular CSS / clean modern design tokens.
- **State Management:** Lightweight React context and hooks for real-time WebSocket feeds.
- **Data Types:** TypeScript interfaces matching backend Pydantic models.

---

## 5. Testing Expectations

1. **Unit Test Coverage:** Every feature extractor, detector, parser, and schema must have corresponding tests in `tests/unit/`.
2. **Determinism:** Tests must be deterministic and execute offline without requiring internet access or active network adapters.
3. **No Heavy Captures in Git:** Never commit raw PCAP captures larger than 1 MB to the repository. Use synthetic packet generators or small minimal fixtures.

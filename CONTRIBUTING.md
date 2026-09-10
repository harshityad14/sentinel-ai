# Contributing to SentinelAI

Thank you for contributing to **SentinelAI**! Whether you are an individual developer or an external collaborator, please adhere to the following standards to ensure production quality, maintainability, and architectural integrity.

---

## 🔒 Mandatory Architectural Invariant

All contributors must respect our foundational security invariant:

> **"The SentinelAI detection pipeline is strictly passive. No component may transmit packets, perform active probing, complete network handshakes, block traffic, or decrypt application payloads."**

### Invariant Rules:
1. **Never transmit packets:** Code that calls `socket.send()`, `scapy.send()`, or emits any packet onto the monitored network will be rejected immediately.
2. **Never attempt decryption:** Do not write code that attempts to break, decrypt, or intercept TLS/SSL payloads. All encrypted traffic analysis must rely on handshake metadata (SNI, cipher suites, JA3/JA4), packet sequence lengths, and timing characteristics.
3. **No blocking or active response:** SentinelAI is a detection and alerting platform, not an inline IPS. Mitigation is strictly advisory.

---

## 🏗️ Monorepo Conventions

The project separates concerns cleanly:
- `packages/models`: Pydantic domain models shared across services.
- `packages/ingestion`: Raw packet capture and header parsing.
- `packages/flow_engine`: Bi-directional 5-tuple flow aggregation.
- `packages/features`: Feature extraction (SPLT, jitter, entropy).
- `packages/detection`: Detectors (rules, statistical, ml, correlation, scoring).
- `packages/ai_agent`: Advisory GenAI Security Analyst.
- `apps/api`: FastAPI REST and WebSocket backend.
- `apps/web`: React + Vite + TypeScript frontend.

**Rule:** Packages must import from `sentinel_models` rather than creating duplicate internal event or alert representations.

---

## 🧪 Development Workflow & Standards

### 1. Code Style
- **Python:** PEP 8 compliance, formatted with `ruff` and `black`, typed with `mypy`.
- **TypeScript:** Strict type checking, formatted with `prettier`, linted with `eslint`.
- Always provide type annotations for public functions and class methods.

### 2. Testing Requirements
- Unit tests must be placed under `tests/unit/`.
- Integration tests must be placed under `tests/integration/`.
- Never commit live or large PCAP files (`> 1 MB`) to git. Use synthetic test fixtures or download hooks.
- All unit tests must pass cleanly:
  ```bash
  python -m unittest discover -s tests/unit
  ```

### 3. Commit Message Guidelines
Follow the Conventional Commits specification:
- `feat(ingestion): add pcap streaming reader`
- `fix(flow_engine): handle tcp fin timeout edge-case`
- `docs(roadmap): update phase 3 deliverables`
- `test(models): add validation tests for alert schemas`
- `refactor(detection): decouple rule evaluator from flow buffer`

---

## 🚀 Pull Request Checklist

Before submitting changes, ensure:
- [ ] Code adheres strictly to the **Passive-Security Invariant**.
- [ ] Type hints are complete and verified.
- [ ] All new logic is covered by unit tests.
- [ ] No temporary files, credentials, or large PCAP captures are staged.
- [ ] Documentation is updated where necessary.

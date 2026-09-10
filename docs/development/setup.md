# SentinelAI — Developer Environment Setup Guide

This guide describes how to configure your local development environment for **SentinelAI** and execute the Phase 1 ingestion and flow engine pipeline.

---

## 1. Prerequisites

Ensure the following tools are installed:
- **Python:** 3.11 or higher (`python --version`)
- **Git:** 2.35 or higher (`git --version`)
- **Pip:** Standard package manager

---

## 2. Repository Setup & Virtual Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/harshityad14/sentinel-ai.git
   cd sentinel-ai
   ```

2. Activate virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install pydantic>=2.5.0 scapy>=2.5.0
   ```

4. Install packages in editable mode:
   ```bash
   pip install -e packages/models
   pip install -e packages/ingestion
   pip install -e packages/flow_engine
   pip install -e packages/features
   pip install -e packages/detection
   pip install -e packages/ai_agent
   ```

---

## 3. Running Phase 1 CLI (`sentinel-ingest`)

SentinelAI provides a high-performance, strictly passive CLI for reading PCAP/PCAPNG files and extracting bidirectional flow records into JSONL.

### Basic Usage
```bash
# Output flows to standard output
python -m sentinel_ingestion.cli -i sample.pcap

# Write flows to a JSONL file
python -m sentinel_ingestion.cli -i sample.pcap -o flows.jsonl

# Configure custom inactivity timeout (e.g., 60 seconds)
python -m sentinel_ingestion.cli -i sample.pcap -o flows.jsonl --timeout 60.0
```

If packages were installed via `pip install -e packages/ingestion`, the console script is directly available:
```bash
sentinel-ingest sample.pcap -o flows.jsonl
```

### CLI Arguments
| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-i` | `--input` | Path to input `.pcap` or `.pcapng` file | Required |
| `-o` | `--output` | Destination file for JSONL output | `stdout` |
| `-t` | `--timeout`| Flow inactivity timeout in seconds | `30.0` |
| `-f` | `--format` | Output format (`jsonl`) | `jsonl` |

---

## 4. Running Tests

Run all unit tests across models, ingestion, flow engine, and CLI:
```bash
# Windows (PowerShell)
$env:PYTHONPATH="packages/models;packages/ingestion;packages/flow_engine;packages/features;packages/detection;packages/ai_agent;tests"
python -m unittest discover -s tests/unit -v

# Linux / macOS
PYTHONPATH="packages/models:packages/ingestion:packages/flow_engine:packages/features:packages/detection:packages/ai_agent:tests" python -m unittest discover -s tests/unit -v
```

---

## 5. Running the Phase 1 Performance Baseline

Execute the synthetic baseline benchmark tool:
```bash
# Windows (PowerShell)
$env:PYTHONPATH="packages/models;packages/ingestion;packages/flow_engine;packages/features;packages/detection;packages/ai_agent;tests"
python tests/benchmarks/benchmark_ingestion.py -n 5000 -f 250

# Linux / macOS
PYTHONPATH="packages/models:packages/ingestion:packages/flow_engine:packages/features:packages/detection:packages/ai_agent:tests" python tests/benchmarks/benchmark_ingestion.py -n 5000 -f 250
```

Expected output:
```text
=======================================================
 SentinelAI Phase 1 Performance Baseline Benchmark
 Workload: 5000 packets across 250 bidirectional flows
=======================================================
Results:
  - Packets Processed:        5,000
  - Bidirectional Flows:      250
  - Execution Time:           ~2.2s
  - Ingestion Throughput:     ~2,200 packets/sec
  - Flow Processing Rate:     ~110 flows/sec
=======================================================
```

---

## 6. Passive-Security Invariant Verification

SentinelAI operates strictly passively:
- No network sockets are opened for transmitting data (`socket.send()`).
- No packets are sent to monitored hosts.
- Captured files are opened strictly in read-only mode (`rb`).
- Payloads are never decrypted.

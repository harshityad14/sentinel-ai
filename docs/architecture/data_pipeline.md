# SentinelAI — Data Pipeline & Feature Extraction

## 1. Pipeline Overview

The SentinelAI data pipeline transforms raw network packets into enriched, structured security events without decrypting payloads or transmitting packets.

```
[Raw Wire / PCAP] 
       │
       ▼  (Zero-copy packet reading)
[Header Decoders] ───► Extract IP, Ports, Proto, TCP Flags, DNS, TLS
       │
       ▼  (5-tuple hash & state tracking)
[Flow Aggregator] ───► Bi-directional sessions with active/inactive timeouts
       │
       ▼  (Feature computation)
[Feature Extractor] ──► SPLT, Inter-Arrival Jitter, Shannon Entropy, Asymmetry
       │
       ▼  (Detection & Telemetry)
[Detection Engine] ──► Alerts, Risk Scores, Throughput & Latency Metrics
```

---

## 2. Ingestion & Header Metadata Extraction

### 2.1 Layer 3 / Layer 4 Headers
- **IPv4 / IPv6:** Source IP, Destination IP, TTL/Hop Limit, Total Packet Length, IP Protocol ID.
- **TCP:** Source Port, Destination Port, Sequence Number, Ack Number, Header Length, Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`), Window Size.
- **UDP:** Source Port, Destination Port, Length.
- **ICMP:** Type, Code (used for network discovery & unreachable tracking).

### 2.2 Unencrypted Protocol Telemetry
- **DNS Telemetry:**
  - Query Name (FQDN)
  - Query Type (`A`, `AAAA`, `TXT`, `MX`, `CNAME`, etc.)
  - Response Code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`)
  - Subdomain count, total domain length, record count.
- **TLS Handshake Metadata:**
  - ClientHello: SNI (Server Name Indication), supported TLS version, offered Cipher Suites, TLS Extensions.
  - ServerHello: Chosen Cipher Suite, negotiated TLS version.
  - Fingerprints: **JA3** (Client fingerprint) and **JA4** (Modern client/server fingerprint).

---

## 3. Stateful Bi-directional Flow Sessionization

### 3.1 Flow Definition
A flow represents a bi-directional communication sequence between two endpoints sharing an identical 5-tuple within an established time window:
$$\text{Flow Key} = \left( \min(\text{IP}_A, \text{IP}_B), \max(\text{IP}_A, \text{IP}_B), \text{Port}_A, \text{Port}_B, \text{Proto} \right)$$

### 3.2 Directional Tracking
- **Forward Direction ($F$):** Packets initiated by the connection originator ($\text{IP}_{\text{src}}$ of the first seen packet).
- **Backward Direction ($B$):** Packets sent in response ($\text{IP}_{\text{dst}}$ of the first seen packet).

### 3.3 Flow Expiration Mechanisms
1. **Inactive Timeout ($\Delta t_{\text{inactive}}$):** If no packet is observed for a flow within $\Delta t_{\text{inactive}}$ (default: $15\,\text{s}$), the flow is deemed terminated and flushed.
2. **Active Timeout ($\Delta t_{\text{active}}$):** Long-lived flows (e.g., persistent SSH sessions, continuous video streams) are flushed periodically at $\Delta t_{\text{active}}$ (default: $60\,\text{s}$) to avoid delayed threat detection.
3. **TCP Termination:** Flows observing `FIN` or `RST` sequences are expired following a short grace period ($2\,\text{s}$) to capture trailing packets.

---

## 4. Feature Extraction & Engineering

All features are derived without inspecting application payloads:

### 4.1 Sequence of Packet Lengths and Times (SPLT)
- Records the signed length and relative arrival time for the first $K$ packets (default $K = 20$) of a flow:
  $$\text{SPLT} = \left[ (s_1 \cdot L_1, \Delta t_1), (s_2 \cdot L_2, \Delta t_2), \dots, (s_K \cdot L_K, \Delta t_K) \right]$$
  where $s_i \in \{+1, -1\}$ denotes direction (forward/backward), $L_i$ is the payload byte length, and $\Delta t_i = t_i - t_{i-1}$ is the inter-packet arrival time.
- **Utility:** Classifies encrypted applications (e.g., distinguishing interactive SSH from file transfer, or identifying C2 beaconing rhythms) without decryption.

### 4.2 Inter-Arrival Timing & Jitter
- Measures the distribution of packet arrival delays:
  $$\mu_{\Delta t} = \frac{1}{N-1} \sum_{i=2}^N (t_i - t_{i-1})$$
  $$\sigma_{\Delta t} = \sqrt{\frac{1}{N-1} \sum_{i=2}^N (\Delta t_i - \mu_{\Delta t})^2}$$
- **Utility:** Low variance ($\sigma_{\Delta t} \approx 0$) or regular periodic spikes indicate automated beaconing (Cobalt Strike, malware heartbeats) rather than human browsing.

### 4.3 Shannon Entropy Analysis
- Measures the information density and randomness of string representations (e.g., domain names):
  $$H(S) = -\sum_{i=1}^M p(c_i) \log_2 p(c_i)$$
  where $p(c_i)$ is the frequency of character $c_i$ in string $S$.
- **Utility:** DGA (Domain Generation Algorithms) generated domains exhibit significantly higher entropy ($H > 3.8$) compared to natural language domains ($H \approx 2.0 - 2.8$).

### 4.4 Flow Volume & Asymmetry Metrics
- **Byte Asymmetry Ratio:**
  $$R_{\text{bytes}} = \frac{\text{Bytes}_{\text{forward}}}{\text{Bytes}_{\text{forward}} + \text{Bytes}_{\text{backward}}}$$
- **Packet Asymmetry Ratio:**
  $$R_{\text{pkts}} = \frac{\text{Packets}_{\text{forward}}}{\text{Packets}_{\text{forward}} + \text{Packets}_{\text{backward}}}$$
- **Utility:** Highlights data exfiltration ($R_{\text{bytes}} \to 1$ with high total volume) or denial of service amplification ($R_{\text{bytes}} \to 0$ with massive inbound response volume).

# SentinelAI — Threat Models & MITRE ATT&CK Mapping

This document specifies the threat models addressed by **SentinelAI** for **SIH 2026 Problem 145**. All threat identification is performed strictly using passive network telemetry without active probing or payload decryption.

---

## Threat Matrix Overview

| # | Threat Name | MITRE Technique | Attack Vector | Passive Indicators |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Volumetric & SYN Flood DDoS** | T1498 (Network Denial of Service) | High-volume packet floods targeting bandwidth or connection tables | Abnormal packet surge, high ratio of SYN to ACK, high rate of incomplete handshakes |
| 2 | **Port & Network Scanning** | T1046 (Network Service Discovery) | Sequential or random sweeps to discover open ports or live hosts | High destination port/IP entropy, high TCP RST/timeout rates, rapid connection bursts |
| 3 | **C2 Beaconing** | T1071 (Application Layer Protocol) | Compromised internal host communicating periodically with external C2 | Regular inter-arrival times, low jitter variance, repetitive connection lengths |
| 4 | **DNS DGA & Tunneling** | T1568.002 (DGA) / T1071.004 (DNS) | Malware generating algorithmic domains or exfiltrating data via DNS queries | High domain Shannon entropy, excessive TXT queries, high NXDOMAIN response rate |
| 5 | **Suspicious Encrypted Flows** | T1573 (Encrypted Channel) | Malicious C2 or data transfer over TLS/HTTPS | Known malicious JA3/JA4 fingerprints, anomalous cipher suites, non-standard SPLT rhythms |
| 6 | **Data Exfiltration** | T1048 (Exfiltration Over Alternative Protocol) | Unauthorized bulk data transfer outside the network perimeter | High outbound-to-inbound byte ratio, prolonged high-throughput bursts off-hours |
| 7 | **Behavioral Anomaly** | T1078 (Valid Accounts / Living off Land) | Deviations from established baseline behavior | Novel destination endpoints, unusual active hours, sudden volumetric deviations |

---

## Detailed Threat Specifications

### 1. Volumetric & State-Exhaustion DDoS (T1498)
- **Mechanics:** Attacker generates massive rates of TCP SYN, UDP, or ICMP packets to saturate upstream bandwidth or deplete OS socket buffers.
- **Passive Detection Logic:**
  - Track moving average packet rate per destination IP.
  - Calculate SYN-to-ACK ratio: in healthy traffic $\frac{\text{SYN}}{\text{ACK}} \approx 1$. Under SYN flood, $\frac{\text{SYN}}{\text{ACK}} \gg 10$.
  - Monitor UDP flood rate: packet arrival rate exceeding dynamic $3\sigma$ threshold for non-DNS/media ports.
- **Explainability:** Emits exact packet arrival rate ($\text{pkts/sec}$), baseline expected rate, and unacknowledged SYN count.

### 2. Port & Network Scanning (T1046)
- **Mechanics:** Reconnaissance tool (e.g., Nmap, Masscan, ZMap) sweeps target IP ranges or ports looking for exposed listening services.
- **Passive Detection Logic:**
  - **Horizontal Scan:** Single source IP sending connection attempts to the same port across $\ge N$ unique destination IPs within time window $W$.
  - **Vertical Scan:** Single source IP sending connection attempts to $\ge M$ distinct ports on a single destination IP.
  - **Failed Handshake Tracking:** Scanners rarely complete full 3-way handshakes; track ratio of failed/reset connections ($R_{\text{fail}} > 0.85$).
- **Explainability:** Emits scanned IP/port ranges, scan duration, and scan velocity (ports/sec).

### 3. Command & Control (C2) Beaconing (T1071)
- **Mechanics:** Remote access trojans (Cobalt Strike, Sliver, Meterpreter) send periodic keep-alive heartbeats to maintain connectivity.
- **Passive Detection Logic:**
  - Group outbound flows by `(src_ip, dst_ip, dst_port)`.
  - Calculate inter-connection intervals $\Delta t = [t_1, t_2, \dots, t_k]$.
  - Compute interval jitter percentage: $\text{Jitter} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} \times 100\%$.
  - Heartbeats with $\text{Jitter} < 15\%$ across $\ge 10$ sessions trigger beaconing alerts.
- **Explainability:** Emits average beacon period (e.g., $30.1\,\text{s}$), calculated jitter percentage, and observation count.

### 4. DNS DGA & Data Tunneling (T1568.002, T1071.004)
- **Mechanics:** Malware computes pseudo-random domain names to evade static domain blacklists, or encodes sensitive data into DNS subdomains (e.g., `base64_data.evil-domain.com`).
- **Passive Detection Logic:**
  - **DGA:** Calculate Shannon entropy of the Second-Level Domain (SLD). Domains with $H(\text{SLD}) > 3.85$ and vowel ratio $< 0.20$ or $> 0.70$ are flagged.
  - **Tunneling:** High frequency of requests to the same apex domain with unique high-length subdomains ($> 30$ characters) or frequent `TXT` / `NULL` query types.
- **Explainability:** Emits queried domain string, calculated Shannon entropy value, vowel ratio, and query volume.

### 5. Suspicious Encrypted Flows (T1573)
- **Mechanics:** Attackers route malicious traffic through TLS/HTTPS to evade deep packet inspection (DPI).
- **Passive Detection Logic:**
  - Extract TLS ClientHello parameters: TLS version, Cipher Suites in order, Extensions, Elliptic Curves, Point Formats.
  - Compute MD5 hash to produce **JA3** / **JA4** fingerprint.
  - Match fingerprint against known malicious client databases (e.g., malware families, Tor, scanning tools).
  - Analyze SPLT feature vector: packet length sequences of malware command exchange differ characteristically from browser web browsing.
- **Explainability:** Emits calculated JA3/JA4 hash, negotiated cipher suite, SNI, and SPLT rhythm classification score.

### 6. Data Exfiltration (T1048)
- **Mechanics:** Insider or adversary transfers internal documents or databases to external cloud storage or remote servers.
- **Passive Detection Logic:**
  - Track directional byte asymmetry: $\frac{\text{Bytes}_{\text{out}}}{\text{Bytes}_{\text{in}}} \gg 5.0$ with total outbound bytes exceeding threshold (e.g., $> 50\,\text{MB}$).
  - Evaluate flow duration and burstiness against typical client workstation profiles.
- **Explainability:** Emits total outbound volume, exfiltration rate, destination host, and historical average transfer comparison.

### 7. Behavioral Anomaly Detection (T1078)
- **Mechanics:** Lateral movement or compromised credentials used off-hours or targeting unusual internal subnets.
- **Passive Detection Logic:**
  - Host profiling: Maintain continuous 7-day baseline of typical communication peers and protocols for internal endpoints.
  - Anomaly scoring: Flag first-time external connections, novel high ports, or traffic spikes outside normal business operating hours.
- **Explainability:** Emits historical baseline expectation vs. observed deviation metrics.

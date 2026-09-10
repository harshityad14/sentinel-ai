# SentinelAI — Feature Engineering Architecture & Catalog

## 1. Overview & Passive Invariant

The SentinelAI Feature Engine consumes stateful `FlowRecord` objects produced by the Flow Engine and derives strongly-typed, normalized security feature vectors (`FeatureVector`) for consumption by downstream detection models (Phase 3).

### 🔒 Passive Analysis Guarantee
```
"The Feature Engine operates exclusively on passively extracted metadata, packet lengths,
arrival timings, and unencrypted protocol handshake structures. It never inspects, accesses,
or decrypts application payloads."
```

---

## 2. Feature Pipeline Architecture

```
                      +────────────────────────+
                      |       FlowRecord       |
                      +────────────────────────+
                                  │
                                  ▼
                   +──────────────────────────────+
                   |   UnifiedFeatureExtractor    |
                   +──────────────────────────────+
                                  │
         ┌────────────────┬───────┴────────┬──────────────┬──────────────┐
         ▼                ▼                ▼              ▼              ▼
+────────────────+ +─────────────+ +──────────────+ +────────────+ +────────────+
| NetworkFeatures| | TCPFeatures | |TimingFeatures| | DNSFeatures| | TLSFeatures|
| (Volumetric &  | | (Flags &    | | (Inter-packet| | (Lexical & | | (Handshake |
|  Rates)        | |  Ratios)    | |  Jitter)     | |  Entropy)  | |  Metadata) |
+────────────────+ +─────────────+ +──────────────+ +────────────+ +────────────+
         │                │                │              │              │
         └────────────────┴───────┬────────┴──────────────┴──────────────┘
                                  ▼
                      +────────────────────────+
                      |     FeatureVector      |
                      |   (Versioned Schema)   |
                      +────────────────────────+
                                  │
                                  ▼
                      +────────────────────────+
                      |   to_flat_dict() /     |
                      |   to_json() Output     |
                      +────────────────────────+
```

---

## 3. Feature Versioning & Governance

- Current Schema Version: **`1.0`**
- All feature definitions are registered in `FeatureRegistry` with:
  - Canonical feature name
  - Data type (`float`, `int`, `bool`, `str`)
  - Functional category (`network`, `tcp`, `timing`, `dns`, `tls`)
  - Implementation status: `IMPLEMENTED` vs `PLANNED`
- Downstream models must reference an explicit `feature_version` to prevent semantic drift.

---

## 4. Missing Data & Explicit Representation Policy

SentinelAI avoids deceptive zeroes (e.g. reporting `0.0` for TCP SYN/ACK ratio on UDP traffic, or `0.0` entropy for unencrypted non-DNS traffic).
- **Non-applicable features** evaluate strictly to `None` in `FeatureVector` and `to_flat_dict()`.
- **Zero-division safety:** Rate calculations on zero-duration flows yield `0.0` via `safe_div()`.

---

## 5. Feature Catalog & Mathematical Formulations

### 5.1 Network Features (`net_*`) — `IMPLEMENTED`

| Feature Name | Type | Formula / Description |
| :--- | :--- | :--- |
| `duration_sec` | float | Active flow duration $\Delta t = t_{\text{end}} - t_{\text{start}}$ |
| `total_packets` | int | $N_{\text{total}} = N_{\text{fwd}} + N_{\text{bwd}}$ |
| `total_bytes` | int | $B_{\text{total}} = B_{\text{fwd}} + B_{\text{bwd}}$ |
| `forward_packets` | int | Packets sent by connection initiator |
| `backward_packets` | int | Packets sent by responder |
| `forward_bytes` | int | Wire bytes sent by initiator |
| `backward_bytes` | int | Wire bytes sent by responder |
| `packets_per_second` | float | $\text{safe\_div}(N_{\text{total}}, \Delta t)$ |
| `bytes_per_second` | float | $\text{safe\_div}(B_{\text{total}}, \Delta t)$ |
| `forward_packets_per_second` | float | $\text{safe\_div}(N_{\text{fwd}}, \Delta t)$ |
| `backward_packets_per_second` | float | $\text{safe\_div}(N_{\text{bwd}}, \Delta t)$ |
| `forward_backward_packet_ratio`| float | $\text{safe\_div}(N_{\text{fwd}}, N_{\text{bwd}})$ |
| `forward_backward_byte_ratio` | float | $\text{safe\_div}(B_{\text{fwd}}, B_{\text{bwd}})$ |
| `byte_asymmetry_ratio` | float | $\text{safe\_div}(B_{\text{fwd}}, B_{\text{total}})$ |
| `mean_packet_size` | float | $\frac{B_{\text{total}}}{N_{\text{total}}}$ |
| `min_packet_size` | int | Minimum recorded wire packet size |
| `max_packet_size` | int | Maximum recorded wire packet size |
| `packet_size_std` | float | $\sigma = \sqrt{\frac{1}{N}\sum (L_i - \mu)^2}$ |

### 5.2 TCP Behavioral Features (`tcp_*`) — `IMPLEMENTED`
*Note: Evaluates to `None` for non-TCP flows.*

| Feature Name | Type | Formula / Description |
| :--- | :--- | :--- |
| `syn_count` | int | Total SYN flags observed |
| `ack_count` | int | Total ACK flags observed |
| `fin_count` | int | Total FIN flags observed |
| `rst_count` | int | Total RST flags observed |
| `psh_count` | int | Total PSH flags observed |
| `urg_count` | int | Total URG flags observed |
| `ece_count` | int | Total ECE flags observed |
| `cwr_count` | int | Total CWR flags observed |
| `syn_ack_ratio` | float | $\text{safe\_div}(\text{SYN}, \text{ACK})$ |
| `rst_ratio` | float | $\text{safe\_div}(\text{RST}, N_{\text{total}})$ |
| `fin_ratio` | float | $\text{safe\_div}(\text{FIN}, N_{\text{total}})$ |

### 5.3 Timing & Inter-Arrival Features (`time_*`)

| Feature Name | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| `mean_inter_arrival_sec` | float | `IMPLEMENTED` | $\mu_{\Delta t} = \text{safe\_div}(\Delta t, N - 1)$ |
| `min_inter_arrival_sec` | float | `IMPLEMENTED` | Minimum packet arrival delta in sequence |
| `max_inter_arrival_sec` | float | `IMPLEMENTED` | Maximum packet arrival delta in sequence |
| `inter_arrival_std_sec` | float | `IMPLEMENTED` | Standard deviation of packet arrival deltas |
| `jitter_ratio` | float | `IMPLEMENTED` | $\text{safe\_div}(\sigma_{\Delta t}, \mu_{\Delta t})$ |
| `burst_count` | int | `IMPLEMENTED` | Count of packets arriving with $\Delta t_i < 0.2 \cdot \mu_{\Delta t}$ |
| `splt_sequence` | str | `PLANNED` | Sequence of Packet Lengths and Times for first $K$ packets |

### 5.4 DNS Query Features (`dns_*`) — `IMPLEMENTED`
*Note: Evaluates to `None` when no DNS query context is present.*

| Feature Name | Type | Formula / Description |
| :--- | :--- | :--- |
| `query_length` | int | Character length of queried FQDN |
| `subdomain_depth` | int | Subdomain labels count: $\max(0, \text{labels} - 2)$ |
| `shannon_entropy` | float | $H(S) = -\sum_{c \in S} p(c) \log_2 p(c)$ |
| `digit_ratio` | float | Ratio of numeric digits to total query length |
| `alphabetic_ratio` | float | Ratio of alphabetic characters to total query length |
| `unique_char_ratio` | float | Ratio of distinct characters to total query length |
| `label_count` | int | Total count of dot-delimited labels |
| `is_nxdomain` | bool | Boolean flag if response code returned `NXDOMAIN` |

### 5.5 TLS Handshake Features (`tls_*`) — `IMPLEMENTED`
*Note: Evaluates to `None` when no TLS handshake metadata is present.*

| Feature Name | Type | Description |
| :--- | :--- | :--- |
| `tls_version` | str | Advertised TLS protocol version string |
| `sni_present` | bool | True if Server Name Indication header was included |
| `cipher_suite_count` | int | Total number of offered cipher suites |
| `ja3_present` | bool | True if JA3 client fingerprint was computed |
| `ja3_hash` | str | MD5 hash of ClientHello JA3 representation |
| `ja4_present` | bool | True if JA4 client fingerprint was computed |
| `ja4_hash` | str | JA4 client fingerprint string |

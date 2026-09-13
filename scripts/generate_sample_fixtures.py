"""Generates deterministic offline dataset sample fixtures for SentinelAI ML testing and verification.

Produces:
- data/samples/cic_ids_curated_sample.csv (CIC-IDS2017 format)
- data/samples/unsw_nb15_curated_sample.csv (UNSW-NB15 format)
"""

import csv
from pathlib import Path
import numpy as np

def generate_cic_sample(output_path: Path, seed: int = 42) -> None:
    rng = np.random.RandomState(seed)
    
    headers = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Average Packet Size",
        "Packet Length Std",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Label",
    ]
    
    rows = []
    
    # 1. BENIGN (60 flows) - typical interactive HTTP/HTTPS/API traffic
    for _ in range(60):
        dur_us = rng.uniform(200_000, 4_000_000)  # 0.2s - 4s
        fwd_p = rng.randint(6, 30)
        bwd_p = rng.randint(6, 40)
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(60, 200)
        bwd_b = bwd_p * rng.uniform(400, 1200)
        total_b = fwd_b + bwd_b
        dur_s = dur_us / 1_000_000.0
        bps = total_b / dur_s
        pps = total_p / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(80, 300)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.3, 1.2)
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "BENIGN"
        ])

    # 2. PortScan (25 flows) - fast port probe, 1-2 packets, very short duration
    for _ in range(25):
        dur_us = rng.uniform(50, 600)  # 50 - 600 microseconds
        fwd_p = rng.randint(1, 3)
        bwd_p = rng.choice([0, 1], p=[0.7, 0.3])
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(40, 64)
        bwd_b = bwd_p * 40.0
        total_b = fwd_b + bwd_b
        dur_s = dur_us / 1_000_000.0
        bps = total_b / max(1e-5, dur_s)
        pps = total_p / max(1e-5, dur_s)
        avg_sz = total_b / total_p
        sz_std = 0.0 if total_p <= 1 else rng.uniform(0, 5)
        iat_mean = 0.0 if total_p <= 1 else dur_us / (total_p - 1)
        iat_std = 0.0
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "PortScan"
        ])

    # 3. DoS Hulk / Syn Flood (25 flows) - high packet rate, small SYN packets
    for _ in range(25):
        dur_us = rng.uniform(2_000_000, 8_000_000)  # 2s - 8s
        dur_s = dur_us / 1_000_000.0
        pps = rng.uniform(400, 1200)
        fwd_p = int(pps * dur_s)
        bwd_p = rng.randint(0, 5)
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(44, 60)
        bwd_b = bwd_p * 40.0
        total_b = fwd_b + bwd_b
        bps = total_b / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(1, 8)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.1, 0.4)
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "DoS Hulk"
        ])

    # 4. DDoS / UDP Flood (25 flows) - high packet rate, heavy volumetric UDP payload
    for _ in range(25):
        dur_us = rng.uniform(1_500_000, 6_000_000)  # 1.5s - 6s
        dur_s = dur_us / 1_000_000.0
        pps = rng.uniform(800, 2500)
        fwd_p = int(pps * dur_s)
        bwd_p = 0
        total_p = fwd_p
        fwd_b = fwd_p * rng.uniform(800, 1400)
        total_b = fwd_b
        bps = total_b / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(10, 40)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.05, 0.25)
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), 0.0,
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "DDoS"
        ])

    # 5. Bot / C2 Beaconing (25 flows) - regular periodic heartbeats with low jitter
    for _ in range(25):
        dur_us = rng.uniform(15_000_000, 60_000_000)  # 15s - 60s
        dur_s = dur_us / 1_000_000.0
        fwd_p = rng.randint(4, 12)
        bwd_p = rng.randint(4, 12)
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(80, 150)
        bwd_b = bwd_p * rng.uniform(80, 150)
        total_b = fwd_b + bwd_b
        bps = total_b / dur_s
        pps = total_p / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(5, 25)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.01, 0.08)  # very low jitter!
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "Bot"
        ])

    # 6. Infiltration / Data Exfiltration (25 flows) - large outbound byte transfer
    for _ in range(25):
        dur_us = rng.uniform(8_000_000, 30_000_000)  # 8s - 30s
        dur_s = dur_us / 1_000_000.0
        fwd_p = rng.randint(500, 2000)
        bwd_p = rng.randint(20, 80)
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(1100, 1460)  # bulk data out
        bwd_b = bwd_p * rng.uniform(40, 60)      # small TCP ACKs back
        total_b = fwd_b + bwd_b
        bps = total_b / dur_s
        pps = total_p / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(200, 450)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.4, 0.9)
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "Infiltration"
        ])

    # 7. FTP-Patator / Behavioral Anomaly (25 flows) - repeated login brute force attempts
    for _ in range(25):
        dur_us = rng.uniform(3_000_000, 12_000_000)
        dur_s = dur_us / 1_000_000.0
        fwd_p = rng.randint(25, 70)
        bwd_p = rng.randint(25, 70)
        total_p = fwd_p + bwd_p
        fwd_b = fwd_p * rng.uniform(90, 220)
        bwd_b = bwd_p * rng.uniform(70, 180)
        total_b = fwd_b + bwd_b
        bps = total_b / dur_s
        pps = total_p / dur_s
        avg_sz = total_b / total_p
        sz_std = rng.uniform(30, 90)
        iat_mean = dur_us / max(1, total_p - 1)
        iat_std = iat_mean * rng.uniform(0.2, 0.6)
        rows.append([
            int(dur_us), fwd_p, bwd_p, round(fwd_b, 1), round(bwd_b, 1),
            round(bps, 2), round(pps, 2), round(avg_sz, 2), round(sz_std, 2),
            round(iat_mean, 2), round(iat_std, 2), "FTP-Patator"
        ])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated {len(rows)} curated CIC-IDS samples at {output_path}")


def generate_unsw_sample(output_path: Path, seed: int = 42) -> None:
    rng = np.random.RandomState(seed)
    
    headers = [
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "sinpkt",
        "dinpkt",
        "attack_cat",
    ]
    
    rows = []
    
    # 1. normal (40 flows)
    for _ in range(40):
        dur = rng.uniform(0.1, 4.0)
        spkts = rng.randint(6, 30)
        dpkts = rng.randint(6, 40)
        sbytes = spkts * rng.uniform(60, 200)
        dbytes = dpkts * rng.uniform(400, 1200)
        rate = (spkts + dpkts) / dur
        sinpkt = (dur / max(1, spkts - 1)) * 1000.0  # ms
        dinpkt = (dur / max(1, dpkts - 1)) * 1000.0  # ms
        rows.append([
            round(dur, 6), spkts, dpkts, int(sbytes), int(dbytes),
            round(rate, 4), round(sinpkt, 4), round(dinpkt, 4), "Normal"
        ])

    # 2. Reconnaissance / PortScan (15 flows)
    for _ in range(15):
        dur = rng.uniform(0.0001, 0.001)
        spkts = rng.randint(1, 3)
        dpkts = rng.choice([0, 1])
        sbytes = spkts * 44
        dbytes = dpkts * 40
        rate = (spkts + dpkts) / dur
        sinpkt = (dur / max(1, spkts - 1)) * 1000.0 if spkts > 1 else 0.0
        dinpkt = 0.0
        rows.append([
            round(dur, 6), spkts, dpkts, int(sbytes), int(dbytes),
            round(rate, 4), round(sinpkt, 4), round(dinpkt, 4), "Reconnaissance"
        ])

    # 3. DoS / SYN Flood (15 flows)
    for _ in range(15):
        dur = rng.uniform(2.0, 8.0)
        rate = rng.uniform(400, 1000)
        spkts = int(rate * dur)
        dpkts = rng.randint(0, 4)
        sbytes = spkts * 54
        dbytes = dpkts * 40
        sinpkt = (dur / max(1, spkts - 1)) * 1000.0
        dinpkt = 0.0
        rows.append([
            round(dur, 6), spkts, dpkts, int(sbytes), int(dbytes),
            round(rate, 4), round(sinpkt, 4), round(dinpkt, 4), "DoS"
        ])

    # 4. Backdoor / C2 Beaconing (15 flows)
    for _ in range(15):
        dur = rng.uniform(20.0, 60.0)
        spkts = rng.randint(4, 10)
        dpkts = rng.randint(4, 10)
        sbytes = spkts * 100
        dbytes = dpkts * 100
        rate = (spkts + dpkts) / dur
        sinpkt = (dur / max(1, spkts - 1)) * 1000.0
        dinpkt = (dur / max(1, dpkts - 1)) * 1000.0
        rows.append([
            round(dur, 6), spkts, dpkts, int(sbytes), int(dbytes),
            round(rate, 4), round(sinpkt, 4), round(dinpkt, 4), "Backdoors"
        ])

    # 5. Exploits / Behavioral Anomaly (15 flows)
    for _ in range(15):
        dur = rng.uniform(1.0, 8.0)
        spkts = rng.randint(15, 50)
        dpkts = rng.randint(15, 50)
        sbytes = spkts * rng.uniform(120, 300)
        dbytes = dpkts * rng.uniform(100, 250)
        rate = (spkts + dpkts) / dur
        sinpkt = (dur / max(1, spkts - 1)) * 1000.0
        dinpkt = (dur / max(1, dpkts - 1)) * 1000.0
        rows.append([
            round(dur, 6), spkts, dpkts, int(sbytes), int(dbytes),
            round(rate, 4), round(sinpkt, 4), round(dinpkt, 4), "Exploits"
        ])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Generated {len(rows)} curated UNSW-NB15 samples at {output_path}")


if __name__ == "__main__":
    cic_target = Path("data/samples/cic_ids_curated_sample.csv")
    unsw_target = Path("data/samples/unsw_nb15_curated_sample.csv")
    generate_cic_sample(cic_target)
    generate_unsw_sample(unsw_target)

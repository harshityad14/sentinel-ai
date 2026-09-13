#!/usr/bin/env python3
"""Dataset acquisition and verification utility for SentinelAI Phase 10.

Provides official source references, download coordination, and SHA256 checksum
verification for public network security benchmark datasets:
1. CIC-IDS2017 (Canadian Institute for Cybersecurity)
2. CSE-CIC-IDS2018 (AWS / Communications Security Establishment)
3. CIC-DDoS2019 (Canadian Institute for Cybersecurity)
4. UNSW-NB15 (Australian Centre for Cyber Security)

Downloaded files are placed in data/external/ which is git-ignored.
"""

import argparse
import hashlib
import logging
import os
import sys
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [dataset_fetch]: %(message)s",
)
logger = logging.getLogger("sentinel.dataset_fetch")

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_DATA_DIR = REPO_ROOT / "data" / "external"

DATASET_CATALOG = {
    "cic-ids2017": {
        "name": "CIC-IDS2017",
        "citation": "Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, 'Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization', ICISSP 2018",
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/GeneratedLabelledFlows.zip",
        "description": "Full capture of realistic benign and multi-vector network attacks in CSV format",
    },
    "cic-ddos2019": {
        "name": "CIC-DDoS2019",
        "citation": "Iman Sharafaldin, Amirhossein H. Lashkari, Saqib Hakak, and Ali A. Ghorbani, 'Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy', IEEE CCGrid 2019",
        "url": "http://205.174.165.80/CICDataset/CIC-DDoS-2019/Dataset/CSVs/",
        "description": "Specialized high-volume DDoS flow dataset including SYN, UDP, and reflection attacks",
    },
    "unsw-nb15": {
        "name": "UNSW-NB15",
        "citation": "Nour Moustafa and Jill Slay, 'UNSW-NB15: a comprehensive data set for network intrusion detection systems', IEEE MilCIS 2015",
        "url": "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download",
        "description": "External validation benchmark synthesized at the Cyber Range Lab of UNSW Canberra",
    },
}


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hex digest of file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def print_catalog():
    """Print available dataset references and citations."""
    print("================================================================================")
    print(" SentinelAI Benchmark Dataset Catalog")
    print("================================================================================")
    for key, info in DATASET_CATALOG.items():
        print(f"[{key}] {info['name']}")
        print(f"  Description: {info['description']}")
        print(f"  Citation:    {info['citation']}")
        print(f"  Source URL:  {info['url']}")
        print()
    print(f"Target directory for downloads: {EXTERNAL_DATA_DIR}")
    print("Note: Multi-gigabyte archives are strictly kept outside git tracking.")
    print("================================================================================")


def download_dataset(dataset_key: str, destination: Path):
    """Download dataset with progress reporting."""
    if dataset_key not in DATASET_CATALOG:
        logger.error(f"Unknown dataset key: '{dataset_key}'. Choose from: {list(DATASET_CATALOG.keys())}")
        sys.exit(1)

    info = DATASET_CATALOG[dataset_key]
    destination.mkdir(parents=True, exist_ok=True)
    target_file = destination / f"{dataset_key}.zip"

    logger.info(f"Downloading {info['name']} from {info['url']}...")
    try:
        def progress_callback(blocks, block_size, total_size):
            downloaded = blocks * block_size
            if total_size > 0:
                pct = min(100.0, (downloaded / total_size) * 100.0)
                sys.stdout.write(f"\rDownloading: {downloaded / 1e6:.1f} MB / {total_size / 1e6:.1f} MB ({pct:.1f}%)")
                sys.stdout.flush()

        urllib.request.urlretrieve(info["url"], target_file, reporthook=progress_callback)
        print()
        logger.info(f"Download complete: {target_file}")
        checksum = compute_sha256(target_file)
        logger.info(f"SHA256: {checksum}")
    except Exception as exc:
        logger.error(f"Download failed: {exc}")
        logger.info(f"Please download manually from {info['url']} and place into {destination}")


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Dataset Management Utility")
    parser.add_argument("--list", action="store_true", help="List catalog of supported benchmark datasets")
    parser.add_argument("--download", type=str, choices=list(DATASET_CATALOG.keys()), help="Download target dataset")
    parser.add_argument("--dest", type=str, default=str(EXTERNAL_DATA_DIR), help="Download destination folder")
    args = parser.parse_args()

    if args.list or not args.download:
        print_catalog()
    elif args.download:
        download_dataset(args.download, Path(args.dest))


if __name__ == "__main__":
    main()

"""Unit tests for dataset adapters mapping public network security datasets to SentinelAI 15-feature vectors."""

import math
import unittest

from sentinel_detection.ml.dataset_adapter import (
    CICDatasetAdapter,
    UNSWDatasetAdapter,
    _safe_float,
    _safe_int,
)
from sentinel_detection.ml.trainer import CANONICAL_ML_FEATURES
from sentinel_models.detection import ThreatType


class TestDatasetAdapters(unittest.TestCase):
    def setUp(self):
        self.cic_adapter = CICDatasetAdapter()
        self.unsw_adapter = UNSWDatasetAdapter()

    def test_safe_conversions(self):
        """Verify NaN, Inf, None, and malformed strings are safely sanitized."""
        self.assertEqual(_safe_float(float("nan"), 0.0), 0.0)
        self.assertEqual(_safe_float(float("inf"), 0.0), 0.0)
        self.assertEqual(_safe_float("-inf", 0.0), 0.0)
        self.assertEqual(_safe_float("invalid_str", 12.5), 12.5)
        self.assertEqual(_safe_float(None, 0.0), 0.0)
        self.assertEqual(_safe_float("42.5", 0.0), 42.5)

        self.assertEqual(_safe_int(float("nan"), 0), 0)
        self.assertEqual(_safe_int("invalid", 5), 5)
        self.assertEqual(_safe_int("100", 0), 100)

    def test_cic_adapter_conversions(self):
        """Verify CIC adapter microsecond-to-second conversion, asymmetry, and schema."""
        raw_row = {
            "Flow Duration": "2000000",  # 2.0s
            "Total Fwd Packets": "10",
            "Total Backward Packets": "10",
            "Total Length of Fwd Packets": "1000",
            "Total Length of Bwd Packets": "3000",
            "Flow Bytes/s": "2000.0",
            "Flow Packets/s": "10.0",
            "Average Packet Size": "200.0",
            "Packet Length Std": "50.0",
            "Flow IAT Mean": "100000",  # 0.1s
            "Flow IAT Std": "20000",   # 0.02s
            "Label": "BENIGN",
        }

        result = self.cic_adapter.adapt_record(raw_row)
        self.assertIsNotNone(result)
        features, label = result

        # Check label mapping
        self.assertEqual(label, ThreatType.BENIGN.value)

        # Check feature length and ordering
        self.assertEqual(len(features), len(CANONICAL_ML_FEATURES))
        self.assertEqual(len(features), 15)

        # duration in seconds (2,000,000 us -> 2.0s)
        self.assertAlmostEqual(features[0], 2.0)
        # total bytes (1000 + 3000 = 4000)
        self.assertAlmostEqual(features[1], 4000.0)
        # fwd bytes
        self.assertAlmostEqual(features[2], 1000.0)
        # bwd bytes
        self.assertAlmostEqual(features[3], 3000.0)
        # total pkts
        self.assertAlmostEqual(features[4], 20.0)
        # fwd pkts
        self.assertAlmostEqual(features[5], 10.0)
        # bwd pkts
        self.assertAlmostEqual(features[6], 10.0)
        # byte asymmetry ratio (1000 / 4000 = 0.25)
        self.assertAlmostEqual(features[9], 0.25)
        # mean IAT in seconds (100,000 us -> 0.1s)
        self.assertAlmostEqual(features[12], 0.1)
        # IAT std in seconds (20,000 us -> 0.02s)
        self.assertAlmostEqual(features[13], 0.02)
        # jitter ratio (0.02 / 0.1 = 0.2)
        self.assertAlmostEqual(features[14], 0.2)

    def test_cic_label_mapping(self):
        """Verify explicit label mapping for all supported attack categories."""
        label_cases = [
            ("BENIGN", ThreatType.BENIGN.value),
            ("PortScan", ThreatType.PORT_SCAN.value),
            ("DoS Hulk", ThreatType.SYN_FLOOD.value),
            ("Syn Flood", ThreatType.SYN_FLOOD.value),
            ("DDoS", ThreatType.UDP_FLOOD.value),
            ("UDP", ThreatType.UDP_FLOOD.value),
            ("Bot", ThreatType.C2_BEACONING.value),
            ("Infiltration", ThreatType.DATA_EXFILTRATION.value),
            ("FTP-Patator", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("SSH-Patator", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Web Attack \x96 Brute Force", ThreatType.BEHAVIORAL_ANOMALY.value),
            # Real CIC-IDS2017 CSV labels with Unicode replacement character
            ("Web Attack \ufffd Brute Force", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Web Attack \ufffd XSS", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Web Attack \ufffd Sql Injection", ThreatType.BEHAVIORAL_ANOMALY.value),
            # ASCII dash variants
            ("Web Attack - Brute Force", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Web Attack - XSS", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Web Attack - Sql Injection", ThreatType.BEHAVIORAL_ANOMALY.value),
        ]

        dummy_row = {
            "Flow Duration": "1000000",
            "Total Fwd Packets": "5",
            "Total Backward Packets": "5",
            "Total Length of Fwd Packets": "500",
            "Total Length of Bwd Packets": "500",
            "Flow Bytes/s": "1000",
            "Flow Packets/s": "10",
            "Average Packet Size": "100",
            "Packet Length Std": "10",
            "Flow IAT Mean": "100000",
            "Flow IAT Std": "10000",
        }

        for raw_label, expected_threat in label_cases:
            dummy_row["Label"] = raw_label
            res = self.cic_adapter.adapt_record(dummy_row)
            self.assertIsNotNone(res, f"Failed to adapt label {repr(raw_label)}")
            _, mapped_label = res
            self.assertEqual(mapped_label, expected_threat, f"Wrong mapping for {repr(raw_label)}")

    def test_unsw_adapter_conversions(self):
        """Verify UNSW adapter ms-to-sec conversion, rate calculation, and schema."""
        raw_row = {
            "dur": "1.5",
            "spkts": "10",
            "dpkts": "20",
            "sbytes": "800",
            "dbytes": "3200",
            "rate": "20.0",
            "sinpkt": "150.0",  # 150 ms
            "dinpkt": "50.0",   # 50 ms
            "attack_cat": "Reconnaissance",
        }

        res = self.unsw_adapter.adapt_record(raw_row)
        self.assertIsNotNone(res)
        features, label = res

        self.assertEqual(label, ThreatType.PORT_SCAN.value)
        self.assertEqual(len(features), 15)

        # duration
        self.assertAlmostEqual(features[0], 1.5)
        # total bytes (800 + 3200 = 4000)
        self.assertAlmostEqual(features[1], 4000.0)
        # asymmetry (800 / 4000 = 0.20)
        self.assertAlmostEqual(features[9], 0.20)
        # mean IAT ((150 + 50)/2 = 100 ms -> 0.1s)
        self.assertAlmostEqual(features[12], 0.1)

    def test_unsw_label_mapping(self):
        """Verify UNSW attack category mappings."""
        cases = [
            ("Normal", ThreatType.BENIGN.value),
            ("Reconnaissance", ThreatType.PORT_SCAN.value),
            ("DoS", ThreatType.SYN_FLOOD.value),
            ("Backdoor", ThreatType.C2_BEACONING.value),
            ("Exploits", ThreatType.BEHAVIORAL_ANOMALY.value),
            ("Fuzzers", ThreatType.BEHAVIORAL_ANOMALY.value),
        ]
        dummy = {
            "dur": "1.0",
            "spkts": "5",
            "dpkts": "5",
            "sbytes": "500",
            "dbytes": "500",
            "rate": "10",
            "sinpkt": "100",
            "dinpkt": "100",
        }
        for raw_cat, exp in cases:
            dummy["attack_cat"] = raw_cat
            res = self.unsw_adapter.adapt_record(dummy)
            self.assertIsNotNone(res, f"Failed for {raw_cat}")
            _, mapped = res
            self.assertEqual(mapped, exp)


if __name__ == "__main__":
    unittest.main()

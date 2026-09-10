"""Unit tests for sentinel-ingest CLI."""

import json
import tempfile
import unittest
from pathlib import Path

from sentinel_ingestion.cli import main
from tests.fixtures.pcap_generator import write_test_pcap


class TestIngestionCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = Path(self.tmp_dir.name) / "test.pcap"
        self.out_path = Path(self.tmp_dir.name) / "flows.jsonl"
        write_test_pcap(self.pcap_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_cli_basic_jsonl_output(self):
        exit_code = main(["--input", str(self.pcap_path), "--output", str(self.out_path)])
        self.assertEqual(exit_code, 0)
        self.assertTrue(self.out_path.exists())

        # Read JSONL file lines
        lines = self.out_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertGreater(len(lines), 0)

        # Verify each line is valid JSON representing a FlowRecord
        for line in lines:
            data = json.loads(line)
            self.assertIn("flow_id", data)
            self.assertIn("source_ip", data)
            self.assertIn("destination_ip", data)
            self.assertIn("total_packets", data)
            self.assertIn("total_bytes", data)

    def test_cli_positional_input(self):
        exit_code = main([str(self.pcap_path), "--output", str(self.out_path)])
        self.assertEqual(exit_code, 0)
        self.assertTrue(self.out_path.exists())

    def test_cli_missing_input_file(self):
        exit_code = main(["--input", "non_existent.pcap"])
        self.assertEqual(exit_code, 1)

    def test_cli_no_arguments(self):
        exit_code = main([])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()

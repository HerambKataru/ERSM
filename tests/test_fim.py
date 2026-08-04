"""
Unit tests for File Integrity Monitor hash computation and baseline generation.
"""

import os
import tempfile
import unittest
from monitors.file_integrity_monitor import FileIntegrityMonitor
from platform.base_adapter import BasePlatformAdapter


class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.temp_dir.name, "test_config.txt")
        with open(self.test_file_path, "w") as f:
            f.write("initial baseline content\n")

        self.baseline_path = os.path.join(self.temp_dir.name, "baseline.json")
        self.fim = FileIntegrityMonitor(
            event_bus=None,
            platform_adapter=BasePlatformAdapter(),
            config={
                "monitored_paths": [self.test_file_path],
                "baseline_path": self.baseline_path
            }
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sha256_computation_and_baseline(self):
        hash1 = self.fim.compute_sha256(self.test_file_path)
        self.assertIsNotNone(hash1)
        self.assertEqual(len(hash1), 64)

        count = self.fim.create_baseline()
        self.assertEqual(count, 1)

        baseline = self.fim.load_baseline()
        self.assertIn(os.path.abspath(self.test_file_path), baseline)
        self.assertEqual(baseline[os.path.abspath(self.test_file_path)]["sha256"], hash1)

    def test_file_modification_detection(self):
        self.fim.create_baseline()

        # Modify file
        with open(self.test_file_path, "w") as f:
            f.write("MODIFIED content!\n")

        hash2 = self.fim.compute_sha256(self.test_file_path)
        baseline = self.fim.load_baseline()
        stored_hash = baseline[os.path.abspath(self.test_file_path)]["sha256"]

        self.assertNotEqual(hash2, stored_hash)


if __name__ == "__main__":
    unittest.main()

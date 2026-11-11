"""
BI Antivirus - Sprint 10 Sandbox & ML Validation Tests
Verifies:
1. Sandbox capability and status reporting (get_capabilities, check_health)
2. Truthful offline simulation reporting (is_simulation=True, MD5, size)
3. Local ML model evaluation on harmless synthetic validation corpus
4. Confusion matrix calculation (TP, FP, TN, FN, precision, recall, FPR, accuracy)
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from bi_antivirus.enterprise.cloud_sandbox import CloudSandboxClient
from bi_antivirus.core.ml_engine import LocalMLEngine


class TestSprint10SandboxAndML(unittest.TestCase):
    """Test suite for Sprint 10 Sandbox abstraction and ML model validation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bi_s10_test_")
        self.sandbox = CloudSandboxClient()
        self.ml_engine = LocalMLEngine(model_dir=Path(self.temp_dir))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_sandbox_capabilities_truthful_disclosure(self):
        """Verify CloudSandboxClient truthfully reports local simulation mode when unconfigured."""
        caps = self.sandbox.get_capabilities()
        self.assertFalse(caps["cloud_configured"])
        self.assertTrue(caps["is_simulation"])
        self.assertEqual(caps["status"], "OFFLINE_SIMULATION")
        self.assertEqual(caps["active_provider_mode"], "LOCAL_SIMULATION")
        self.assertIn(".exe", caps["supported_file_types"])

        health = self.sandbox.check_health()
        self.assertTrue(health["healthy"])
        self.assertTrue(health["local_simulation_ready"])
        self.assertFalse(health["cloud_api_available"])

    def test_02_simulation_report_metadata(self):
        """Verify simulated dynamic detonation includes is_simulation flag, MD5, and size."""
        sample_bytes = b"MZ\x90\x00\x03\x00\x00\x00VirtualAlloc CreateRemoteThread"
        ticket = self.sandbox.submit_sample(data=sample_bytes, file_name="injector_test.exe")
        self.assertEqual(ticket.provider_type, "LOCAL_SIMULATION")

        report = self.sandbox.get_analysis_report(ticket.ticket_id)
        self.assertEqual(report.status, "COMPLETED")
        self.assertTrue(report.is_simulation)
        self.assertGreater(len(report.sample_md5), 0)
        self.assertEqual(report.sample_size, len(sample_bytes))
        self.assertIn("T1055 - Process Injection", report.mitre_techniques)

    def test_03_ml_corpus_evaluation_metrics(self):
        """Verify LocalMLEngine.evaluate_corpus computes accurate confusion matrix and metrics."""
        # Define harmless synthetic test corpus
        corpus = [
            # Benign text samples
            (b"This is a harmless text file content.", "BENIGN"),
            (b"Another clean corporate report document.", "BENIGN"),
            ({"is_pe": False}, "BENIGN"),
            # Malicious synthetic PE feature sets
            ({
                "is_pe": True,
                "overall_entropy": 7.6,
                "sections": [{"entropy": 7.9, "raw_size": 1024, "virtual_size": 8192, "is_rwx": True}],
                "has_packer_sections": True,
                "mitigations": {"dep": False, "aslr": False, "cfg": False},
                "suspicious_apis_by_category": {
                    "PROCESS_INJECTION": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    "NETWORK_C2": ["InternetOpenA"],
                },
                "has_overlay": True,
                "data_directories": {"SECURITY": {"present": False}},
            }, "MALICIOUS"),
            ({
                "is_pe": True,
                "overall_entropy": 7.8,
                "sections": [{"entropy": 7.8, "raw_size": 2048, "virtual_size": 10000, "is_rwx": True}],
                "has_packer_sections": True,
                "mitigations": {"dep": False, "aslr": False, "cfg": False},
                "suspicious_apis_by_category": {
                    "RANSOMWARE_CRYPTO": ["CryptEncrypt"],
                },
                "has_overlay": True,
                "data_directories": {"SECURITY": {"present": False}},
            }, "MALICIOUS"),
        ]

        results = self.ml_engine.evaluate_corpus(corpus)
        self.assertEqual(results["total_samples"], 5)
        self.assertEqual(results["true_positives"], 2)
        self.assertEqual(results["true_negatives"], 3)
        self.assertEqual(results["false_positives"], 0)
        self.assertEqual(results["false_negatives"], 0)
        self.assertEqual(results["precision"], 1.0)
        self.assertEqual(results["recall"], 1.0)
        self.assertEqual(results["false_positive_rate"], 0.0)
        self.assertEqual(results["accuracy"], 1.0)
        self.assertIn("confusion_matrix", results)


if __name__ == "__main__":
    unittest.main()

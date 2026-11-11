"""
BI Antivirus - Test Suite for False-Positive & Reliability Framework
Verifies:
- Harmless test corpus generation in D: drive scratch space
- Zero false positives on benign PE executables, valid ZIP archives, and high-entropy documents
- Graceful error handling with zero crashes across diverse malformed PE structures
- Evaluation performance, latency benchmarks, and memory footprint
"""

import unittest
import secrets
from pathlib import Path

from bi_antivirus.config import SCRATCH_DIR
from bi_antivirus.core.corpus_evaluator import CorpusEvaluator
from bi_antivirus.core.pe_classifier import PEClassifier
from bi_antivirus.monitors.ransomware_shield import RansomwareShield


class TestFalsePositives(unittest.TestCase):
    """Test suite evaluating false positives and engine reliability against harmless corpus."""

    def setUp(self):
        uid = secrets.token_hex(4)
        self.corpus_dir = SCRATCH_DIR / f"test_fp_corpus_{uid}"
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.evaluator = CorpusEvaluator(corpus_root=self.corpus_dir)
        self.pe_classifier = PEClassifier()
        self.ransomware_shield = RansomwareShield(watch_dirs=[self.corpus_dir])

    def tearDown(self):
        self.evaluator.cleanup()

    def test_benign_pe_clean_classification(self):
        """Verify that a standard harmless PE executable is classified clean with 0 false positives."""
        pe_path = self.corpus_dir / "clean_sample.exe"
        self.evaluator.generate_benign_pe(pe_path)

        res = self.pe_classifier.inspect_pe_file(pe_path)
        self.assertTrue(res["is_pe"])
        self.assertEqual(res["format"], "PE32 (32-bit)")
        self.assertIn(res["verdict"], ("BENIGN_PROBABLE", "CLEAN", "BENIGN", "LOW_RISK"))
        self.assertNotEqual(res["verdict"], "MALICIOUS_PROBABLE")
        self.assertLess(res["risk_score"], 45)

    def test_benign_high_entropy_doc_false_positive_resistance(self):
        """Verify that legitimate high-entropy ASCII text (base64 tokens) does not trigger ransomware alert."""
        doc_path = self.corpus_dir / "api_token_export.txt"
        self.evaluator.generate_benign_high_entropy_doc(doc_path)

        alert = self.ransomware_shield.record_file_entropy(doc_path)
        self.assertIsNone(alert, "Legitimate printable ASCII text must not be flagged as ransomware ciphertext")

    def test_benign_zip_archive_clean(self):
        """Verify that a standard zip archive does not falsely trigger ransomware or PE alerts."""
        zip_path = self.corpus_dir / "archive_backup.zip"
        self.evaluator.generate_benign_zip(zip_path)

        # 1. PE classifier should recognise not a PE without errors
        pe_res = self.pe_classifier.inspect_pe_file(zip_path)
        self.assertFalse(pe_res["is_pe"])
        self.assertIsNotNone(pe_res["error"])

        # 2. Ransomware shield should not flag standard zip extension as high-entropy text
        alert = self.ransomware_shield.record_file_entropy(zip_path)
        self.assertIsNone(alert)

    def test_malformed_pes_crash_resilience(self):
        """Verify engine gracefully handles truncated, corrupted, and oversized PE headers without crashing."""
        malformed_dir = self.corpus_dir / "malformed_tests"
        malformed_dir.mkdir(parents=True, exist_ok=True)
        malformed_files = self.evaluator.generate_malformed_pes(malformed_dir)

        self.assertGreaterEqual(len(malformed_files), 5)
        for mf in malformed_files:
            try:
                res = self.pe_classifier.inspect_pe_file(mf)
                self.assertIsInstance(res, dict)
                # Ensure either not PE or valid error reported
                if not res.get("is_pe", False):
                    self.assertIsNotNone(res.get("error"))
            except Exception as e:
                self.fail(f"Engine crashed unexpectedly on malformed sample {mf.name}: {e}")

    def test_full_corpus_evaluation_metrics(self):
        """Execute full automated corpus evaluation and verify 0% FP rate and performance targets."""
        report = self.evaluator.evaluate_false_positives(
            pe_classifier=self.pe_classifier,
            ransomware_shield=self.ransomware_shield,
        )

        self.assertGreater(report["total_samples_evaluated"], 0)
        self.assertEqual(report["crashes_count"], 0, f"Engine crashed: {report['crashes_details']}")
        self.assertTrue(report["all_malformed_handled_safely"])

        # Target: 0% False Positive Rate on benign corpus
        self.assertEqual(report["false_positives_count"], 0, f"False positives detected: {report['false_positives_details']}")
        self.assertEqual(report["false_positive_rate_percent"], 0.0)

        # Performance targets: mean latency < 100ms
        perf = report["performance"]
        self.assertLess(perf["mean_latency_ms"], 100.0)
        self.assertGreater(perf["peak_memory_mb"], 0.0)


if __name__ == "__main__":
    unittest.main()

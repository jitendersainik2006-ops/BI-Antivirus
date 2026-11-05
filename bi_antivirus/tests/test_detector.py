"""
Test Suite: Threat Detection Engine and Heuristics
"""

import unittest
from pathlib import Path
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.database.signatures import SignatureDatabase, EICAR_PLAIN

FIXTURES_DIR = Path(r"D:\bit defender\bi_antivirus\tests\fixtures")

class TestThreatDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()

    def test_signature_hash_detection(self):
        sig_file = FIXTURES_DIR / "bi_test_signature.txt"
        self.assertTrue(sig_file.exists())
        result = self.detector.analyze_file(sig_file)
        self.assertTrue(result["is_threat"])
        self.assertEqual(result["detection_type"], "SIGNATURE_HASH")
        self.assertEqual(result["threat_name"], "BI-Standard-Validation-Test-Signature")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["risk_score"], 100)

    def test_eicar_pattern_in_memory(self):
        # Validate pattern engine without exposing plain file on disk to OS real-time hooks
        matches = self.detector.sig_db.match_patterns(EICAR_PLAIN.encode("utf-8"))
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0]["rule_name"], "RULE_EICAR_EXACT")

    def test_clean_file_false_positive_prevention(self):
        clean_file = FIXTURES_DIR / "clean_document.txt"
        self.assertTrue(clean_file.exists())
        result = self.detector.analyze_file(clean_file)
        self.assertFalse(result["is_threat"], "Clean document must never trigger as threat (false-positive prevention)")
        self.assertEqual(result["severity"], "CLEAN")
        self.assertEqual(result["risk_score"], 0)

    def test_ransom_heuristic_detection(self):
        ransom_file = FIXTURES_DIR / "fake_ransom_heuristic.txt"
        self.assertTrue(ransom_file.exists())
        result = self.detector.analyze_file(ransom_file)
        self.assertTrue(result["is_threat"])
        self.assertIn("Ransomware", result["threat_name"])

    def test_double_extension_heuristic(self):
        double_ext_file = FIXTURES_DIR / "suspicious_double_ext.pdf.exe"
        self.assertTrue(double_ext_file.exists())
        result = self.detector.analyze_file(double_ext_file)
        self.assertTrue(result["is_threat"])
        self.assertTrue(any("SuspiciousDoubleExtension" in flag for flag in result.get("heuristic_flags", [])))

    def test_shannon_entropy(self):
        low_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ent_low = ThreatDetector.calculate_shannon_entropy(low_data)
        self.assertEqual(ent_low, 0.0)

        high_data = bytes(range(256)) * 4
        ent_high = ThreatDetector.calculate_shannon_entropy(high_data)
        self.assertGreaterEqual(ent_high, 7.8)

if __name__ == "__main__":
    unittest.main()

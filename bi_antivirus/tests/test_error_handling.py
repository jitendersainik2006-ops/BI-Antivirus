"""
Test Suite: Error Handling and Edge Cases
"""

import unittest
from pathlib import Path
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.monitors.web_protection import WebProtection
from bi_antivirus.core.updater import UpdateManager

class TestErrorHandling(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()
        self.qm = QuarantineManager()
        self.web = WebProtection()
        self.updater = UpdateManager()

    def test_nonexistent_file_analysis(self):
        fake_path = Path(r"D:\non_existent_folder_123\fake_virus.exe")
        res = self.detector.analyze_file(fake_path)
        self.assertFalse(res["is_threat"])
        self.assertIn("error", res)

    def test_nonexistent_quarantine_restore(self):
        ok, msg = self.qm.restore_file("INVALID-QUARANTINE-ID-999")
        self.assertFalse(ok)
        self.assertIn("not found", msg.lower())

    def test_invalid_url_web_check(self):
        res = self.web.check_url("ht!tp://:invalid-domain@@#")
        # Engine should gracefully handle without crashing
        self.assertIn("is_threat", res)

    def test_corrupted_update_pack(self):
        bad_json = "NOT_A_JSON_STRING_{{invalid"
        res = self.updater.apply_update_pack(bad_json)
        self.assertFalse(res["success"])
        self.assertIn("error", res)

if __name__ == "__main__":
    unittest.main()

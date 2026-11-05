"""
Test Suite: File Scanner and Scan History Recording
"""

import unittest
from pathlib import Path
from bi_antivirus.core.scanner import FileScanner
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.database.history import HistoryDatabase

FIXTURES_DIR = Path(r"D:\bit defender\bi_antivirus\tests\fixtures")
TEST_HIST_DB = Path(r"D:\bit defender\data\test_scanner_history.db")

class TestFileScanner(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()
        self.history_db = HistoryDatabase(db_path=TEST_HIST_DB)
        self.scanner = FileScanner(detector=self.detector, history_db=self.history_db)

    def test_custom_folder_scan(self):
        progress_events = []
        def on_progress(p):
            progress_events.append(p)

        res = self.scanner.scan_path(FIXTURES_DIR, progress_cb=on_progress)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreater(res["files_scanned"], 0)
        self.assertGreater(res["threats_count"], 0)
        self.assertTrue(len(progress_events) > 0)

        # Check detected threats
        threat_names = [t["threat_name"] for t in res["threats"]]
        self.assertTrue(any("BI-Standard-Validation-Test-Signature" in name or "Ransomware" in name for name in threat_names))

    def test_scan_history_recorded(self):
        sessions = self.history_db.get_recent_scans(limit=1)
        self.assertTrue(len(sessions) > 0)
        latest = sessions[0]
        self.assertEqual(latest["status"], "COMPLETED")
        self.assertGreater(latest["files_scanned"], 0)

    def test_exclusion_filtering(self):
        excl_paths = ["fixtures"]
        excl_exts = [".pdf"]
        is_excl_1 = self.scanner._is_excluded(Path(r"D:\test\sample.pdf"), [], excl_exts)
        self.assertTrue(is_excl_1)

        is_excl_2 = self.scanner._is_excluded(Path(r"D:\bit defender\bi_antivirus\tests\fixtures\clean.txt"), excl_paths, [])
        self.assertTrue(is_excl_2)

if __name__ == "__main__":
    unittest.main()

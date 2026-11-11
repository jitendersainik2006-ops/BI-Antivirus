"""
Test Suite: USB & Removable Media Sentinel
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.monitors.usb_sentinel import USBSentinel

D_DRIVE_SCRATCH = Path(r"D:\bit defender\data\crypto_test_scratch")

class TestUSBSentinel(unittest.TestCase):

    def setUp(self):
        D_DRIVE_SCRATCH.mkdir(parents=True, exist_ok=True)
        self.mock_drive = Path(tempfile.mkdtemp(prefix="bi_mock_usb_", dir=str(D_DRIVE_SCRATCH)))

    def tearDown(self):
        if self.mock_drive.exists():
            shutil.rmtree(self.mock_drive, ignore_errors=True)

    def test_clean_drive_root(self):
        (self.mock_drive / "My_Photos").mkdir()
        (self.mock_drive / "work_document.docx").write_text("Clean file content")

        res = USBSentinel.audit_drive_root(str(self.mock_drive))
        self.assertFalse(res["is_threat"])
        self.assertEqual(res["status"], "CLEAN")
        self.assertEqual(res["threats_count"], 0)

    def test_malicious_autorun_worm_detection(self):
        # Create malicious autorun.inf
        autorun = self.mock_drive / "autorun.inf"
        autorun.write_text("[autorun]\nopen=malware.exe\naction=Open Folder\nshellexecute=payload.bat\n")

        res = USBSentinel.audit_drive_root(str(self.mock_drive))
        self.assertTrue(res["is_threat"])
        self.assertEqual(res["status"], "THREAT_DETECTED")
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertTrue(any("AutorunExecution" in t["threat_name"] for t in res["threats"]))

    def test_shortcut_worm_pattern_detection(self):
        # Simulate USB shortcut worm replacing 5 folders with .lnk files
        for i in range(5):
            (self.mock_drive / f"folder_{i}.lnk").write_text("LNK_PAYLOAD")

        res = USBSentinel.audit_drive_root(str(self.mock_drive))
        self.assertTrue(res["is_threat"])
        self.assertTrue(any("ShortcutHijack" in t["threat_name"] for t in res["threats"]))

if __name__ == "__main__":
    unittest.main()

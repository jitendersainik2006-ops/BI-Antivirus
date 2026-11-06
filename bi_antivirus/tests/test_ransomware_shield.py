"""
Test Suite: Ransomware Shield & Canary Decoy Defense
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.monitors.ransomware_shield import RansomwareShield

class TestRansomwareShield(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bi_test_ransom_"))
        self.shield = RansomwareShield(watch_dirs=[self.temp_dir])

    def tearDown(self):
        self.shield.stop()
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_canary_deployment_and_integrity(self):
        deployed = self.shield.deploy_canaries()
        self.assertEqual(deployed, 1)

        # Baseline check must report zero violations
        violations = self.shield.check_canary_integrity()
        self.assertEqual(len(violations), 0)

        # Simulate tampering with the canary file (Ransomware encryption)
        canary_file = list(self.shield.canaries.keys())[0]
        with open(canary_file, "r+b") as f:
            f.write(b"ENCRYPTED_BY_TEST_RANSOMWARE_SIMULATION_BYTES")

        # Now integrity check must detect the alteration!
        violations_after = self.shield.check_canary_integrity()
        self.assertEqual(len(violations_after), 1)
        self.assertEqual(violations_after[0]["violation_type"], "CANARY_ENCRYPTED_OR_MODIFIED")
        self.assertEqual(violations_after[0]["severity"], "CRITICAL")

    def test_ransom_note_drop_interception(self):
        note_file = self.temp_dir / "readme_to_decrypt.txt"
        alert = self.shield.record_file_mutation(note_file)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "RANSOM_NOTE_DROPPED")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("Ransomware.ExtortionNote", alert["threat_name"])

    def test_mutation_burst_detection(self):
        # Trigger 3 fast mutations with .lockbit extension
        f1 = self.temp_dir / "document1.docx.lockbit"
        f2 = self.temp_dir / "spreadsheet2.xlsx.lockbit"
        f3 = self.temp_dir / "database3.db.lockbit"

        a1 = self.shield.record_file_mutation(f1)
        self.assertEqual(a1["type"], "SUSPICIOUS_EXTENSION_MUTATION")

        a2 = self.shield.record_file_mutation(f2)
        self.assertEqual(a2["type"], "SUSPICIOUS_EXTENSION_MUTATION")

        # 3rd mutation within window triggers active encryption burst alert!
        a3 = self.shield.record_file_mutation(f3)
        self.assertIsNotNone(a3)
        self.assertEqual(a3["type"], "RANSOMWARE_BURST_ATTACK")
        self.assertEqual(a3["severity"], "CRITICAL")

if __name__ == "__main__":
    unittest.main()

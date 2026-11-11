"""
BI Antivirus - Test Suite for Ransomware Shield Improvements
Verifies:
- Shannon entropy math on structured plaintext vs random ciphertext
- File entropy transition detection (plaintext to high-entropy ciphertext)
- High-entropy document heuristic alerts
- Harmless simulation harness execution completely contained in D: drive scratch space
- Recovery guidance presence and completeness
"""

import os
import unittest
import secrets
from pathlib import Path

from bi_antivirus.monitors.ransomware_shield import (
    RansomwareShield,
    calculate_shannon_entropy,
    RECOVERY_GUIDANCE,
)
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.config import SCRATCH_DIR


class TestRansomwareImprovements(unittest.TestCase):
    """Test suite for Ransomware Shield entropy analysis and simulation harness."""

    def setUp(self):
        uid = secrets.token_hex(4)
        self.scratch_dir = SCRATCH_DIR / f"test_ransom_{uid}"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.scratch_dir / f"test_ransom_history_{uid}.db"
        self.history_db = HistoryDatabase(db_path=self.db_path)
        self.shield = RansomwareShield(
            watch_dirs=[self.scratch_dir],
            history_db=self.history_db,
        )

    def tearDown(self):
        for f in self.scratch_dir.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            self.scratch_dir.rmdir()
        except Exception:
            pass

    def test_shannon_entropy_calculation(self):
        """Verify entropy math distinguishes plaintext from high-entropy ciphertext."""
        plaintext = b"Standard ASCII document content for corporate security policy. " * 30
        h_plain = calculate_shannon_entropy(plaintext)
        self.assertTrue(3.0 <= h_plain <= 5.0, f"Expected low entropy, got: {h_plain}")

        ciphertext = secrets.token_bytes(4096)
        h_cipher = calculate_shannon_entropy(ciphertext)
        self.assertGreaterEqual(h_cipher, 7.8, f"Expected high entropy, got: {h_cipher}")

    def test_file_entropy_transition_alert(self):
        """Verify that transitioning a file from low to high entropy generates a critical alert."""
        sample_file = self.scratch_dir / "user_notes.txt"
        
        # 1. Write benign low-entropy plaintext and record baseline
        sample_file.write_bytes(b"Normal user financial planning notes for next quarter. " * 20)
        alert1 = self.shield.record_file_entropy(sample_file)
        self.assertIsNone(alert1, "Baseline recording should not trigger alert")

        # 2. Simulate encryption: rewrite same file with high-entropy bytes
        sample_file.write_bytes(secrets.token_bytes(2048))
        alert2 = self.shield.record_file_entropy(sample_file)
        self.assertIsNotNone(alert2, "Entropy transition must trigger alert")
        self.assertEqual(alert2["type"], "RANSOMWARE_ENTROPY_SPIKE")
        self.assertGreaterEqual(alert2["current_entropy"], 7.2)
        self.assertGreaterEqual(alert2["entropy_delta"], 2.0)
        self.assertIn("recovery_guidance", alert2)

    def test_high_entropy_document_detection(self):
        """Verify that a newly seen high-entropy document file triggers an alert."""
        random_doc = self.scratch_dir / "confidential_export.csv"
        random_doc.write_bytes(secrets.token_bytes(1024))

        alert = self.shield.record_file_entropy(random_doc)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "RANSOMWARE_HIGH_ENTROPY_TEXT")
        self.assertGreaterEqual(alert["current_entropy"], 7.6)

    def test_harmless_simulation_scenario(self):
        """Verify controlled harmless simulation harness runs and self-cleans safely."""
        sim_dir = self.scratch_dir / "scenario_run"
        res = self.shield.simulate_ransomware_scenario(scratch_dir=sim_dir)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreater(res["files_simulated"], 0)
        self.assertGreater(res["alerts_intercepted"], 0)
        self.assertTrue(res["containment_verified"])
        self.assertTrue(res["burst_detected"] or res["ransom_note_detected"] or res["entropy_spike_detected"])
        self.assertEqual(res["recovery_guidance"], RECOVERY_GUIDANCE)

        # Verify simulation files were cleaned up
        remaining_files = list(sim_dir.glob("*")) if sim_dir.exists() else []
        self.assertEqual(len(remaining_files), 0, "Simulation harness must clean up all test files")

    def test_recovery_guidance_contents(self):
        """Verify recovery guidance contains all essential administrative incident response steps."""
        self.assertIn("Host Isolation", RECOVERY_GUIDANCE)
        self.assertIn("Process Termination", RECOVERY_GUIDANCE)
        self.assertIn("Canary Verification", RECOVERY_GUIDANCE)
        self.assertIn("Volume Shadow", RECOVERY_GUIDANCE)
        self.assertIn("Quarantine Vault", RECOVERY_GUIDANCE)


if __name__ == "__main__":
    unittest.main()

"""
Test Suite: Quarantine Manager - Isolation, Reversible Restore, and Purge
"""

import unittest
import shutil
from pathlib import Path
from bi_antivirus.core.quarantine import QuarantineManager

TEST_VAULT_DIR = Path(r"D:\bit defender\quarantine\test_vault")
TEST_DB_PATH = Path(r"D:\bit defender\data\test_quarantine.db")
SCRATCH_DIR = Path(r"D:\bit defender\quarantine\scratch")

class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        TEST_VAULT_DIR.mkdir(parents=True, exist_ok=True)
        SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self.qm = QuarantineManager(vault_dir=TEST_VAULT_DIR, db_path=TEST_DB_PATH)

    def tearDown(self):
        shutil.rmtree(SCRATCH_DIR, ignore_errors=True)

    def test_quarantine_and_reversible_restore(self):
        # 1. Create a dummy test file
        test_file = SCRATCH_DIR / "sample_suspicious_payload.bin"
        original_content = b"CRITICAL_MALWARE_SIMULATION_BYTES_1234567890_TEST"
        with open(test_file, "wb") as f:
            f.write(original_content)

        threat_info = {
            "threat_name": "Test.Simulated.Payload",
            "threat_family": "Trojan",
            "severity": "HIGH",
            "file_hash": "dummyhash123",
        }

        # 2. Quarantine file
        res = self.qm.quarantine_file(test_file, threat_info)
        self.assertTrue(res["success"])
        self.assertFalse(test_file.exists(), "Original file must be removed from risky location")

        quarantine_id = res["quarantine_id"]
        vault_file = Path(res["vault_path"])
        self.assertTrue(vault_file.exists(), "Quarantined file must exist in encrypted vault")

        # Verify vault content is ciphered and does not match raw original bytes directly
        with open(vault_file, "rb") as f_vault:
            vault_bytes = f_vault.read()
        self.assertNotEqual(vault_bytes, original_content, "Vault bytes must be encrypted/transformed")

        # 3. Reversibly Restore file
        restore_ok, restore_msg = self.qm.restore_file(quarantine_id)
        self.assertTrue(restore_ok, f"Restore failed: {restore_msg}")
        self.assertTrue(test_file.exists(), "Restored file must reappear at original location")

        # 4. Verify 100% byte integrity
        with open(test_file, "rb") as f_restored:
            restored_content = f_restored.read()
        self.assertEqual(restored_content, original_content, "Restored file must match original bytes exactly")

    def test_purge_quarantine(self):
        test_file = SCRATCH_DIR / "to_be_purged.bin"
        with open(test_file, "wb") as f:
            f.write(b"SAMPLE_PURGE_DATA")

        res = self.qm.quarantine_file(test_file, {"threat_name": "PurgeTest"})
        quarantine_id = res["quarantine_id"]
        vault_file = Path(res["vault_path"])
        self.assertTrue(vault_file.exists())

        purge_ok, purge_msg = self.qm.purge_file(quarantine_id)
        self.assertTrue(purge_ok)
        self.assertFalse(vault_file.exists(), "Vault file must be deleted upon purge")

if __name__ == "__main__":
    unittest.main()

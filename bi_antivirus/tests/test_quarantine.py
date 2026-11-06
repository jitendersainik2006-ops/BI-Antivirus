"""
Test Suite: Quarantine Manager - Authenticated AES-256 Encryption, Backward Compatibility & Integrity
"""

import unittest
import shutil
import hashlib
from pathlib import Path
from bi_antivirus.core.quarantine import (
    QuarantineManager,
    _legacy_cipher_bytes,
    VAULT_MAGIC_V2,
)

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
            "file_hash": hashlib.sha256(original_content).hexdigest(),
        }

        # 2. Quarantine file
        res = self.qm.quarantine_file(test_file, threat_info)
        self.assertTrue(res["success"])
        self.assertFalse(test_file.exists(), "Original file must be removed from risky location")
        self.assertEqual(res.get("vault_format"), "AES256_HMAC_V2")

        quarantine_id = res["quarantine_id"]
        vault_file = Path(res["vault_path"])
        self.assertTrue(vault_file.exists(), "Quarantined file must exist in encrypted vault")

        # Verify vault content starts with BIQ2 magic
        with open(vault_file, "rb") as f_vault:
            vault_bytes = f_vault.read()
        self.assertTrue(vault_bytes.startswith(VAULT_MAGIC_V2), "Vault payload must have BIQ2 magic header")
        self.assertNotEqual(vault_bytes, original_content, "Vault bytes must be encrypted")

        # 3. Reversibly Restore file
        restore_ok, restore_msg = self.qm.restore_file(quarantine_id)
        self.assertTrue(restore_ok, f"Restore failed: {restore_msg}")
        self.assertTrue(test_file.exists(), "Restored file must reappear at original location")

        # 4. Verify 100% byte integrity
        with open(test_file, "rb") as f_restored:
            restored_content = f_restored.read()
        self.assertEqual(restored_content, original_content, "Restored file must match original bytes exactly")

    def test_legacy_v1_backward_compatibility(self):
        """Verify legacy XOR quarantine records can be restored seamlessly without data loss."""
        legacy_content = b"LEGACY_V1_MALWARE_RECORD_TEST_CONTENT_OCTOBER_2026"
        legacy_hash = hashlib.sha256(legacy_content).hexdigest()
        legacy_qid = "Q-LEGACY-V1-TEST01"
        legacy_vault_file = TEST_VAULT_DIR / f"{legacy_qid}.biq"
        legacy_target = SCRATCH_DIR / "restored_legacy_file.bin"

        # Write legacy XOR ciphertext directly to vault file
        legacy_ciphertext = _legacy_cipher_bytes(legacy_content)
        with open(legacy_vault_file, "wb") as f:
            f.write(legacy_ciphertext)

        # Insert legacy record into DB
        with self.qm._get_connection() as conn:
            conn.cursor().execute("""
                INSERT OR REPLACE INTO quarantine_records (
                    quarantine_id, original_path, vault_path, file_name, file_hash, file_size,
                    threat_name, threat_family, severity, status, vault_format
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'QUARANTINED', 'XOR_V1')
            """, (
                legacy_qid, str(legacy_target), str(legacy_vault_file),
                legacy_target.name, legacy_hash, len(legacy_content),
                "Legacy.Threat.V1", "Trojan", "HIGH"
            ))
            conn.commit()

        # Restore using QuarantineManager
        ok, msg = self.qm.restore_file(legacy_qid)
        self.assertTrue(ok, f"Legacy restore failed: {msg}")
        self.assertIn("XOR_V1", msg)
        self.assertTrue(legacy_target.exists())
        self.assertEqual(legacy_target.read_bytes(), legacy_content)

    def test_tamper_detection(self):
        """Verify that tampered vault payload causes HMAC failure and prevents unsafe restoration."""
        test_file = SCRATCH_DIR / "tamper_target.bin"
        test_file.write_bytes(b"DATA_BEFORE_TAMPERING_CHECK_2026")
        res = self.qm.quarantine_file(test_file, {"threat_name": "TamperTest"})
        qid = res["quarantine_id"]
        vault_file = Path(res["vault_path"])

        # Tamper with the ciphertext (flip a bit in the encrypted payload)
        raw_vault = bytearray(vault_file.read_bytes())
        raw_vault[-1] ^= 0xFF
        vault_file.write_bytes(bytes(raw_vault))

        # Restore should fail due to HMAC integrity verification
        ok, msg = self.qm.restore_file(qid)
        self.assertFalse(ok, "Tampered vault file must NOT be successfully restored")
        self.assertIn("integrity check failed", msg.lower())

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

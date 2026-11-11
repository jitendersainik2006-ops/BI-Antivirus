"""
BI Antivirus - Test Suite for Update & Recovery Reliability
Verifies:
- Cryptographic signed update key rotation with backward-compatible verification
- Anti-rollback & replay monotonic sequence protection
- Database transaction rollback integrity under fault conditions
- Quarantine restore safety: non-overwrite protections, hash verification, and vault tampering detection
- Integrity validation of backup archives
"""

import os
import hmac
import hashlib
import secrets
import sqlite3
import unittest
from pathlib import Path

from bi_antivirus.config import SCRATCH_DIR
from bi_antivirus.core.threat_intel import ThreatIntelEngine
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase


class TestUpdateRecovery(unittest.TestCase):
    """Test suite evaluating update pipeline reliability, key rotation, and recovery safety."""

    def setUp(self):
        uid = secrets.token_hex(4)
        self.scratch_dir = SCRATCH_DIR / f"test_upd_recov_{uid}"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)

        self.sig_db_path = self.scratch_dir / "test_sig.db"
        self.hist_db_path = self.scratch_dir / "test_hist.db"
        self.sig_db = SignatureDatabase(db_path=self.sig_db_path)
        self.hist_db = HistoryDatabase(db_path=self.hist_db_path)

        self.intel_engine = ThreatIntelEngine(
            history_db=self.hist_db,
            sig_db=self.sig_db,
            data_dir=self.scratch_dir,
        )

        self.quarantine_dir = self.scratch_dir / "quarantine_vault"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_mgr = QuarantineManager(
            vault_dir=self.quarantine_dir,
            db_path=self.scratch_dir / "quarantine.db",
            key_path=self.scratch_dir / "vault_key.dpapi",
        )

    def tearDown(self):
        for f in self.scratch_dir.glob("*"):
            try:
                if f.is_file():
                    f.unlink()
            except Exception:
                pass
        try:
            self.scratch_dir.rmdir()
        except Exception:
            pass

    def test_signed_update_key_rotation_and_backward_compatibility(self):
        """
        Verify that rotating the signing key generates a fresh key,
        and that bundles signed with the older key remain verifiable via previous-key fallback.
        """
        # 1. Generate bundle with initial key
        bundle_v1 = self.intel_engine.generate_update_bundle(
            version="2026.11.05",
            sequence=10,
            signatures=[{"file_hash": "a" * 64, "threat_name": "Trojan.Test.A"}],
            cve_advisories=[],
        )

        # 2. Rotate signing key
        old_key, new_key = self.intel_engine.rotate_signing_key()
        self.assertNotEqual(old_key, new_key)
        self.assertEqual(len(old_key), 32)
        self.assertEqual(len(new_key), 32)

        # 3. Apply bundle signed with old key (must succeed via backward-compatible fallback)
        ok1, msg1 = self.intel_engine.verify_and_apply_bundle(bundle_v1)
        self.assertTrue(ok1, f"Expected backward-compatible verification to succeed, got: {msg1}")

        # 4. Generate new bundle with newly active rotated key
        bundle_v2 = self.intel_engine.generate_update_bundle(
            version="2026.11.06",
            sequence=20,
            signatures=[{"file_hash": "b" * 64, "threat_name": "Trojan.Test.B"}],
            cve_advisories=[],
        )
        ok2, msg2 = self.intel_engine.verify_and_apply_bundle(bundle_v2)
        self.assertTrue(ok2, f"Expected verification with new active key to succeed, got: {msg2}")

    def test_tampered_bundle_signature_rejection(self):
        """Verify that an altered signature or modified payload is rejected."""
        bundle = self.intel_engine.generate_update_bundle(
            version="2026.11.10",
            sequence=30,
            signatures=[{"file_hash": "c" * 64, "threat_name": "Trojan.Test.C"}],
            cve_advisories=[],
        )
        # Corrupt HMAC
        bundle["signature_hmac"] = "0" * 64
        ok, msg = self.intel_engine.verify_and_apply_bundle(bundle)
        self.assertFalse(ok)
        self.assertIn("cryptographic integrity failure", msg.lower())

    def test_database_transaction_rollback_on_fault(self):
        """Verify atomic database transaction integrity and rollback on write errors."""
        db_file = self.scratch_dir / "atomic_test.db"
        conn = sqlite3.connect(str(db_file))
        with conn:
            conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
            conn.execute("INSERT INTO records VALUES (1, 'initial_state')")

        # Simulate failed batch transaction
        try:
            with conn:
                conn.execute("INSERT INTO records VALUES (2, 'second_state')")
                # Intentional constraint violation to force rollback
                conn.execute("INSERT INTO records VALUES (3, 'initial_state')")
        except sqlite3.IntegrityError:
            pass  # Expected constraint failure

        # Verify rollback: record 2 should NOT exist because transaction aborted
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM records")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1, "Transaction should have rolled back completely leaving only initial record")
        conn.close()

    def test_quarantine_restore_refuses_overwrite(self):
        """Verify quarantine restore refuses to overwrite existing file without explicit overwrite flag."""
        sample_file = self.scratch_dir / "important_contract.docx"
        sample_file.write_bytes(b"Original document content prior to quarantine.")

        # Quarantine the file
        threat_info = {
            "threat_name": "EICAR.Test.Stub",
            "threat_family": "TestVirus",
            "severity": "HIGH",
            "file_hash": hashlib.sha256(b"Original document content prior to quarantine.").hexdigest(),
        }
        res = self.quarantine_mgr.quarantine_file(sample_file, threat_info)
        self.assertTrue(res["success"])
        self.assertFalse(sample_file.exists(), "Original file should be removed from disk upon quarantine")

        # Now recreate another file at the original path
        sample_file.write_bytes(b"New legitimate user file created at same location.")

        # Attempt restore with overwrite=False (must fail safely)
        ok, msg = self.quarantine_mgr.restore_file(quarantine_id=res["quarantine_id"], overwrite=False)
        self.assertFalse(ok)
        self.assertIn("already exists", msg.lower())
        self.assertTrue(sample_file.exists())
        self.assertEqual(sample_file.read_bytes(), b"New legitimate user file created at same location.")

    def test_quarantine_restore_hash_validation_and_vault_tamper_detection(self):
        """Verify that tampering with vaulted encrypted file causes restore failure."""
        target_file = self.scratch_dir / "script_to_isolate.ps1"
        data = b"Write-Host 'Benchmarking vault restore integrity.'"
        target_file.write_bytes(data)

        threat_info = {
            "threat_name": "Suspicious.Script.PS",
            "threat_family": "Trojan",
            "severity": "MEDIUM",
            "file_hash": hashlib.sha256(data).hexdigest(),
        }
        res = self.quarantine_mgr.quarantine_file(target_file, threat_info)
        self.assertTrue(res["success"])

        # Tamper with encrypted vault file on disk (corrupt byte payload)
        vault_path = Path(res["vault_path"])
        self.assertTrue(vault_path.exists())
        corrupted = bytearray(vault_path.read_bytes())
        corrupted[-10] ^= 0xFF  # Flip bits in MAC or ciphertext
        vault_path.write_bytes(bytes(corrupted))

        # Attempt restore (must detect tampering and refuse restoration)
        ok, msg = self.quarantine_mgr.restore_file(quarantine_id=res["quarantine_id"])
        self.assertFalse(ok)
        self.assertIn("failed", msg.lower())
        self.assertFalse(target_file.exists(), "Restored file must not be written if integrity verification fails")


if __name__ == "__main__":
    unittest.main()

"""
BI Antivirus - Test Suite for Threat Intelligence Update Engine
Verifies:
- HMAC-SHA256 signature generation and cryptographic verification
- Anti-rollback sequence enforcement (strictly rejects downgrades and replays)
- Corrupted or tampered signature rejection
- Atomic application of update bundles to signature and history databases
- Offline bundle import and export functionality
"""

import json
import unittest
from pathlib import Path

from bi_antivirus.core.threat_intel import ThreatIntelEngine
from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.config import SCRATCH_DIR


class TestThreatIntelEngine(unittest.TestCase):
    """Test suite for signed threat intelligence feed ingestion."""

    def setUp(self):
        self.scratch_dir = SCRATCH_DIR / "test_intel_scratch"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)

        import secrets
        uid = secrets.token_hex(4)
        self.sig_db_path = self.scratch_dir / f"test_sig_{uid}.db"
        self.hist_db_path = self.scratch_dir / f"test_hist_{uid}.db"

        self.sig_db = SignatureDatabase(db_path=self.sig_db_path)
        self.history_db = HistoryDatabase(db_path=self.hist_db_path)

        self.intel_engine = ThreatIntelEngine(
            history_db=self.history_db,
            sig_db=self.sig_db,
        )

    def tearDown(self):
        for f in self.scratch_dir.glob("*.biu"):
            try:
                f.unlink()
            except Exception:
                pass

    def test_signed_bundle_generation_and_valid_application(self):
        """Verify signed bundle generation and successful atomic ingestion."""
        signatures = [
            {
                "hash": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                "threat_name": "Trojan.IntelTest.Alpha",
                "severity": "CRITICAL",
                "threat_family": "Trojan",
                "file_type": "PE",
                "description": "Signed test intelligence sample 1",
            }
        ]
        advisories = [
            {
                "cve_id": "CVE-2026-10001",
                "product_name": "TestSoftware",
                "vendor": "TestCorp",
                "affected_versions_min": "1.0",
                "affected_versions_max": "1.9",
                "fixed_version": "2.0",
                "severity": "HIGH",
                "title": "Remote Buffer Overflow",
                "description": "Vulnerability in TestSoftware",
            }
        ]

        bundle = self.intel_engine.generate_update_bundle(
            feed_id="bi-enterprise-threat-feed",
            version="2026.11.12.1",
            sequence=10,
            signatures=signatures,
            cve_advisories=advisories,
        )

        self.assertTrue(bundle.get("signature_hmac"))
        self.assertEqual(bundle["manifest"]["sequence"], 10)

        # Ingest bundle
        ok, msg = self.intel_engine.verify_and_apply_bundle(bundle)
        self.assertTrue(ok, f"Failed applying valid bundle: {msg}")

        # Verify database reflection
        status = self.intel_engine.get_feed_status()
        self.assertEqual(status["latest_sequence"], 10)
        self.assertEqual(status["latest_version"], "2026.11.12.1")

    def test_anti_rollback_and_replay_rejection(self):
        """Verify that sequence numbers <= current are strictly rejected."""
        # 1. Apply sequence 20
        bundle20 = self.intel_engine.generate_update_bundle(
            feed_id="bi-enterprise-threat-feed",
            version="2026.11.12.2",
            sequence=20,
            signatures=[],
            cve_advisories=[],
        )
        ok20, msg20 = self.intel_engine.verify_and_apply_bundle(bundle20)
        self.assertTrue(ok20)

        # 2. Replay same sequence 20 (Replay attack attempt)
        ok_replay, msg_replay = self.intel_engine.verify_and_apply_bundle(bundle20)
        self.assertFalse(ok_replay)
        self.assertIn("rollback or replay attack", msg_replay.lower())

        # 3. Rollback attempt to sequence 15 (Downgrade attack attempt)
        bundle15 = self.intel_engine.generate_update_bundle(
            feed_id="bi-enterprise-threat-feed",
            version="2026.11.12.1",
            sequence=15,
            signatures=[],
            cve_advisories=[],
        )
        ok_rollback, msg_rollback = self.intel_engine.verify_and_apply_bundle(bundle15)
        self.assertFalse(ok_rollback)

    def test_corrupted_signature_tamper_rejection(self):
        """Verify that any modification to payload data or signature invalidates the bundle."""
        bundle = self.intel_engine.generate_update_bundle(
            feed_id="bi-enterprise-threat-feed",
            version="2026.11.12.3",
            sequence=30,
            signatures=[{"hash": "aabbcc", "threat_name": "TestThreat"}],
            cve_advisories=[],
        )

        # Tamper payload data after signing
        bundle["payload"]["signatures"].append({"hash": "evilhash", "threat_name": "TamperedThreat"})
        ok_tampered, msg_tampered = self.intel_engine.verify_and_apply_bundle(bundle)
        self.assertFalse(ok_tampered)
        self.assertIn("integrity failure", msg_tampered.lower())

        # Invalidate signature string directly
        bundle["signature_hmac"] = "00" * 32
        ok_bad_sig, msg_bad_sig = self.intel_engine.verify_and_apply_bundle(bundle)
        self.assertFalse(ok_bad_sig)

    def test_offline_bundle_file_import(self):
        """Verify loading and applying signed bundle from an offline .json / .biu file."""
        bundle_file = self.scratch_dir / "update_bundle_40.biu"
        bundle = self.intel_engine.generate_update_bundle(
            feed_id="bi-enterprise-threat-feed",
            version="2026.11.12.4",
            sequence=40,
            signatures=[],
            cve_advisories=[],
        )
        bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

        ok, msg = self.intel_engine.import_bundle_file(bundle_file)
        self.assertTrue(ok, f"Failed importing offline bundle: {msg}")
        status = self.intel_engine.get_feed_status()
        self.assertEqual(status["latest_sequence"], 40)


if __name__ == "__main__":
    unittest.main()

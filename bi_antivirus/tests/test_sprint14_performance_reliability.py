"""
BI Antivirus - Sprint 14 Automated Test Suite
Reliability, Performance Optimization & Engine Resilience:
- Compiled pattern cache verification and cache invalidation
- Database WAL journal mode, busy timeouts, and index verification
- Database PRAGMA integrity check and atomic online backup
- Quarantine vault integrity auditing and missing file detection
- EDR incident graph bounded memory management and LRU cache pruning
- mTLS transport client retries with exponential backoff
- Security audit log automatic rotation and size bounding
"""

import os
import sys
import time
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure root path is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.core.incident_graph import IncidentGraphEngine, EDRIncident
from bi_antivirus.enterprise.mtls_transport import MTLSClient
from bi_antivirus.core.logger import SecurityLogger


class TestSprint14PerformanceReliability(unittest.TestCase):
    """Sprint 14 Performance, Reliability, and Resource Resilience Test Suite."""

    def setUp(self):
        self.test_dir = PROJECT_DIR / "data" / f"test_sprint14_{int(time.time() * 1000)}"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import gc
        gc.collect()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_pattern_cache_and_invalidation(self):
        """Verify SignatureDatabase caches compiled regex patterns and invalidates cleanly."""
        sig_db = SignatureDatabase(db_path=self.test_dir / "test_sig.db")
        self.assertIsNone(sig_db._compiled_patterns_cache)

        sample = b"Harmless file with vssadmin delete shadows command for test"
        matches = sig_db.match_patterns(sample)
        self.assertIsNotNone(sig_db._compiled_patterns_cache)
        self.assertGreater(len(sig_db._compiled_patterns_cache), 0)
        self.assertTrue(any(m["rule_name"] == "RULE_RANSOM_SHADOW_DELETE" for m in matches))

        # Test invalidation
        sig_db.invalidate_pattern_cache()
        self.assertIsNone(sig_db._compiled_patterns_cache)

        # Repopulates on next call
        matches_2 = sig_db.match_patterns(sample)
        self.assertIsNotNone(sig_db._compiled_patterns_cache)
        self.assertEqual(len(matches), len(matches_2))

    def test_02_database_wal_mode_and_indexes(self):
        """Verify HistoryDatabase configures WAL mode and generates performance indexes."""
        hist_db = HistoryDatabase(db_path=self.test_dir / "test_hist.db")

        with hist_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0].lower()
            self.assertIn(journal_mode, ("wal", "memory"))

            cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
            index_names = {row[0] for row in cursor.fetchall()}

            self.assertIn("idx_threats_hash", index_names)
            self.assertIn("idx_threats_session", index_names)
            self.assertIn("idx_sessions_started", index_names)
            self.assertIn("idx_edr_severity", index_names)

    def test_03_database_integrity_check_and_backup(self):
        """Verify PRAGMA integrity check passes and database physical backup is restorable."""
        db_path = self.test_dir / "source_hist.db"
        hist_db = HistoryDatabase(db_path=db_path)

        hist_db.record_threat(
            session_id="SESS-TEST-01",
            file_path="D:\\test\\malware.exe",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=2048,
            threat_name="Test.Threat",
            threat_family="Trojan",
            severity="HIGH",
        )

        # Integrity Check
        ok, msg = hist_db.check_integrity()
        self.assertTrue(ok)
        self.assertIn("ok", msg)

        # Online Backup
        backup_path = self.test_dir / "backup_hist.db"
        backup_ok = hist_db.create_backup(backup_path)
        self.assertTrue(backup_ok)
        self.assertTrue(backup_path.exists())

        # Verify backup contains the record
        restored_db = HistoryDatabase(db_path=backup_path)
        threats = restored_db.get_threat_history(limit=5)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["threat_name"], "Test.Threat")

    def test_04_quarantine_integrity_audit(self):
        """Verify QuarantineManager.verify_vault_integrity detects intact and missing records."""
        q_dir = self.test_dir / "vault"
        q_db = self.test_dir / "quarantine.db"
        qm = QuarantineManager(vault_dir=q_dir, db_path=q_db)

        # Create dummy file to quarantine
        sample_file = self.test_dir / "sample.exe"
        sample_file.write_bytes(b"MZ" + b"\x00" * 200)

        res = qm.quarantine_file(sample_file, {"threat_name": "Test.Malware", "severity": "HIGH"})
        self.assertTrue(res["success"])

        # Run integrity check - should be healthy
        audit = qm.verify_vault_integrity()
        self.assertEqual(audit["total_records"], 1)
        self.assertEqual(audit["intact_records"], 1)
        self.assertEqual(audit["missing_records"], 0)
        self.assertTrue(audit["all_healthy"])

        # Simulate missing vault file on disk
        vault_file = Path(res["vault_path"])
        vault_file.unlink()

        audit_after_unlink = qm.verify_vault_integrity()
        self.assertEqual(audit_after_unlink["missing_records"], 1)
        self.assertFalse(audit_after_unlink["all_healthy"])

    def test_05_incident_graph_memory_bounding(self):
        """Verify IncidentGraphEngine caps in-memory incidents and prunes oldest gracefully."""
        graph = IncidentGraphEngine(max_memory_incidents=10)

        # Ingest 15 distinct events
        for i in range(15):
            graph.ingest_event("PROCESS_SPAWN", {
                "pid": 1000 + i,
                "process_name": f"test_proc_{i}.exe",
                "cmdline": f"test_proc_{i}.exe -arg",
            })

        # Must not exceed maximum memory bound + prune buffer
        self.assertLessEqual(len(graph.incidents), 10)
        self.assertGreater(len(graph.incidents), 0)

    def test_06_mtls_client_exponential_retry(self):
        """Verify MTLSClient.send_request applies retries on unreachable host without hanging."""
        from bi_antivirus.enterprise.fleet_database import FleetDatabase
        from bi_antivirus.enterprise.pki_manager import PKIManager

        pki_dir = self.test_dir / "pki"
        pki_dir.mkdir(parents=True, exist_ok=True)
        fdb = FleetDatabase(pki_dir / "fleet.db")
        pki = PKIManager(pki_dir=pki_dir, fleet_db=fdb)
        ca_crt, _ = pki.ensure_root_ca()
        cli_crt, cli_key = pki.issue_client_certificate("EP-BENCH-01", validity_days=30)

        client = MTLSClient(
            endpoint_id="EP-BENCH-01",
            ca_cert_path=ca_crt,
            client_cert_path=cli_crt,
            client_key_path=cli_key,
            server_host="127.0.0.1",
            server_port=65432,  # Closed port
        )

        start = time.perf_counter()
        resp = client.send_request("PING", {"test": True}, timeout=0.1, max_retries=2, backoff_sec=0.05)
        elapsed = time.perf_counter() - start

        self.assertEqual(resp["status"], "ERROR")
        self.assertIn("error", resp)
        self.assertLess(elapsed, 2.0)

    def test_07_logger_auto_rotation(self):
        """Verify SecurityLogger automatically rotates log files when reaching max_bytes."""
        log_file = self.test_dir / "test_sec.log"
        logger = SecurityLogger(log_path=log_file, max_bytes=500, backup_count=2)

        # Write enough events to trigger multiple rotations
        for i in range(20):
            logger.log_event("INFO", "TEST", f"Event message payload {i} with padding " + ("X" * 40))

        self.assertTrue(log_file.exists())
        rotated_1 = self.test_dir / "test_sec.log.1"
        self.assertTrue(rotated_1.exists())
        self.assertLessEqual(log_file.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()

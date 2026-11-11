"""
BI Antivirus - Sprint 15 Automated Test Suite
Windows Integration, Pre-Flight Diagnostics, and Crash Recovery:
- WindowsCompatibilityAuditor full audit and environmental checks
- Python 64-bit runtime and standard library dependencies inspection
- Storage D: drive compliance and disk write permission audit
- SQLite database integrity checks and WAL capability
- CrashRecoveryManager single-instance lock file lifecycle
- Stale lock detection and crash recovery from previous abnormal termination
- Startup recovery: orphaned temporary vault file pruning and checkpoints
"""

import os
import sys
import time
import json
import shutil
import unittest
from pathlib import Path

# Ensure root path is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.core.windows_compat import WindowsCompatibilityAuditor
from bi_antivirus.core.recovery_manager import CrashRecoveryManager
from bi_antivirus.core.logger import SecurityLogger


class TestSprint15WindowsIntegration(unittest.TestCase):
    """Sprint 15 Windows Integration, Diagnostics, and Recovery Test Suite."""

    def setUp(self):
        self.test_dir = PROJECT_DIR / "data" / f"test_sprint15_{int(time.time() * 1000)}"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import gc
        gc.collect()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_windows_compatibility_auditor_full_run(self):
        """Verify WindowsCompatibilityAuditor executes complete audit and produces structured report."""
        auditor = WindowsCompatibilityAuditor(project_root=PROJECT_DIR)
        report = auditor.run_full_audit()

        self.assertIn("overall_readiness", report)
        self.assertIn(report["overall_readiness"], ("READY", "NEEDS_ATTENTION"))
        self.assertIn("checks", report)

        checks = report["checks"]
        self.assertIn("python", checks)
        self.assertIn("windows", checks)
        self.assertIn("privileges", checks)
        self.assertIn("storage", checks)
        self.assertIn("sqlite", checks)
        self.assertIn("cryptography", checks)
        self.assertIn("defender_coexistence", checks)

    def test_02_python_environment_inspection(self):
        """Verify check_python_environment accurately reports version, bitness, and dependencies."""
        auditor = WindowsCompatibilityAuditor(project_root=PROJECT_DIR)
        py_data = auditor.check_python_environment()

        self.assertEqual(py_data["status"], "PASSED")
        self.assertTrue(py_data["is_64bit"])
        self.assertTrue(py_data["is_supported"])
        self.assertEqual(len(py_data["missing_modules"]), 0)
        self.assertIn("3.", py_data["version"])

    def test_03_storage_d_drive_compliance(self):
        """Verify check_storage_d_drive verifies D: root and write permissions."""
        auditor = WindowsCompatibilityAuditor(project_root=PROJECT_DIR)
        storage_data = auditor.check_storage_d_drive()

        self.assertEqual(storage_data["status"], "PASSED")
        self.assertTrue(storage_data["is_d_drive"])
        self.assertTrue(storage_data["write_accessible"])
        self.assertTrue(storage_data["has_adequate_space"])
        self.assertGreater(storage_data["free_space_gb"], 0.0)

    def test_04_sqlite_databases_health_audit(self):
        """Verify check_sqlite_integrity verifies SQLite engine and database files."""
        auditor = WindowsCompatibilityAuditor(project_root=PROJECT_DIR)
        sqlite_data = auditor.check_sqlite_integrity()

        self.assertEqual(sqlite_data["status"], "PASSED")
        self.assertTrue(sqlite_data["all_databases_healthy"])
        self.assertIsNotNone(sqlite_data["sqlite_version"])
        self.assertGreater(len(sqlite_data["databases"]), 0)

    def test_05_crash_recovery_lock_lifecycle(self):
        """Verify CrashRecoveryManager acquires, maintains, and releases lock file."""
        rec_mgr = CrashRecoveryManager(data_dir=self.test_dir)
        self.assertFalse(rec_mgr.lock_file.exists())

        # Acquire lock
        acquired, msg = rec_mgr.acquire_lock()
        self.assertTrue(acquired)
        self.assertTrue(rec_mgr.lock_file.exists())

        with open(rec_mgr.lock_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["pid"], os.getpid())

        # Second acquire by same process returns True
        acq2, _ = rec_mgr.acquire_lock()
        self.assertTrue(acq2)

        # Release lock
        released = rec_mgr.release_lock()
        self.assertTrue(released)
        self.assertFalse(rec_mgr.lock_file.exists())

    def test_06_crash_recovery_stale_lock_detection(self):
        """Verify CrashRecoveryManager detects dead PID in lock file as prior crash."""
        rec_mgr = CrashRecoveryManager(data_dir=self.test_dir)

        # Simulate a dead PID lock file
        dead_pid = 999999
        fake_lock = {
            "pid": dead_pid,
            "acquired_at": "2026-11-10 12:00:00",
            "timestamp": time.time() - 3600,
            "executable": "python.exe",
        }
        with open(rec_mgr.lock_file, "w", encoding="utf-8") as f:
            json.dump(fake_lock, f)

        # Run startup recovery
        report = rec_mgr.perform_startup_recovery()
        self.assertEqual(report["status"], "RECOVERED")
        self.assertTrue(report["previous_unclean_shutdown"])
        self.assertTrue(report["lock_acquired"])
        self.assertTrue(any("unexpected termination" in ev for ev in report["recovery_events"]))

        rec_mgr.release_lock()

    def test_07_recovery_manager_startup_cleanup(self):
        """Verify perform_startup_recovery prunes orphaned .tmp vault files and checks DBs."""
        rec_mgr = CrashRecoveryManager(data_dir=self.test_dir)
        report = rec_mgr.perform_startup_recovery()

        self.assertIn("database_checks", report)
        self.assertIn("history", report["database_checks"])
        self.assertIn("signatures", report["database_checks"])
        self.assertIn("quarantine", report["database_checks"])
        self.assertTrue(report["lock_acquired"])

        rec_mgr.release_lock()


if __name__ == "__main__":
    unittest.main()

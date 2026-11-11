"""
Unit and Integration Tests for Hyper-V Sandbox Proof of Concept (POC) Subsystem
Tests:
- Non-destructive Hyper-V availability and capability probing.
- Disposable isolated VM configuration validation:
  * Resource bounds (RAM <= 2048 MB, vCPU <= 2).
  * Internal Virtual Switch isolation (Zero LAN/WAN).
  * Execution timeout ceilings (<= 60.0 seconds).
  * Snapshot revert declaration.
- Administrator authorization gate.
- Harmless synthetic test sample execution and telemetry collection.
- Timeout enforcement.
- Suspicious behavioral indicator detection (ransomware file touch, network attempt).
- Disposable workspace cleanup.
- Sandbox audit log persistence in database.
- Administrative audit trail verification.
"""

import unittest
import tempfile
import shutil
import time
from pathlib import Path

from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.sandbox_manager import HyperVSandboxManager


class TestSandboxPOC(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bi_sbx_test_"))
        self.db = FleetDatabase(self.temp_dir / "fleet_test.db")
        self.admin_token = "ADMIN-SANDBOX-AUTH-TOKEN-2026"
        self.sandbox = HyperVSandboxManager(
            fleet_db=self.db,
            admin_token=self.admin_token,
            sandbox_dir=self.temp_dir / "sandbox",
        )

        # Create benign harmless test sample
        self.benign_sample = self.temp_dir / "harmless_calc_test.py"
        self.benign_sample.write_text("result = 2 + 2\nprint('Benign run complete')\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_hyperv_availability_probe(self):
        """Verify non-destructive Hyper-V capability probe returns structured report."""
        status = self.sandbox.check_hyperv_availability()
        self.assertIsInstance(status, dict)
        self.assertIn("hyperv_available", status)
        self.assertIn("vmms_installed", status)
        self.assertIn("vmms_running", status)
        self.assertIn("isolation_mode_supported", status)
        self.assertIn("status_summary", status)

    def test_02_disposable_vm_configuration_boundaries(self):
        """Verify strict isolation boundaries and resource ceilings."""
        # Request excessive resources
        cfg = self.sandbox.generate_disposable_vm_config(
            vm_name="TEST-VM",
            ram_mb=16384,
            vcpu_count=16,
            timeout_seconds=300.0,
        )

        # Enforced ceilings
        self.assertEqual(cfg["resources"]["ram_mb"], 2048)
        self.assertEqual(cfg["resources"]["vcpu_count"], 2)
        self.assertEqual(cfg["isolation_boundaries"]["execution_timeout_sec"], 60.0)

        # Enforced network isolation
        self.assertEqual(cfg["virtual_switch"]["type"], "Internal")
        self.assertFalse(cfg["virtual_switch"]["allow_external_traffic"])

        # Enforced disabled integrations
        self.assertTrue(cfg["isolation_boundaries"]["disable_guest_file_sharing"])
        self.assertTrue(cfg["isolation_boundaries"]["disable_clipboard_sharing"])
        self.assertTrue(cfg["isolation_boundaries"]["disable_drive_redirection"])

    def test_03_admin_authorization_gate(self):
        """Verify execution attempt without valid administrator token is rejected."""
        ok, msg, record = self.sandbox.execute_harmless_sample(
            sample_path=self.benign_sample,
            admin_token="FORGED-ADMIN-TOKEN",
        )
        self.assertFalse(ok)
        self.assertEqual(msg, "UNAUTHORIZED_ADMIN_TOKEN")
        self.assertIsNone(record)

    def test_04_missing_sample_path_rejection(self):
        """Verify execution of non-existent sample path is rejected."""
        missing = self.temp_dir / "non_existent.exe"
        ok, msg, record = self.sandbox.execute_harmless_sample(
            sample_path=missing,
            admin_token=self.admin_token,
        )
        self.assertFalse(ok)
        self.assertIn("SAMPLE_NOT_FOUND", msg)

    def test_05_benign_sample_execution_and_telemetry(self):
        """Verify benign harmless sample executes cleanly and records audit entry."""
        ok, msg, record = self.sandbox.execute_harmless_sample(
            sample_path=self.benign_sample,
            admin_token=self.admin_token,
            timeout_seconds=5.0,
            admin_id="sec_tester",
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "SANDBOX_EXECUTION_SUCCESS")
        self.assertIsNotNone(record)
        self.assertEqual(record.sample_name, "harmless_calc_test.py")
        self.assertEqual(record.verdict, "BENIGN")
        self.assertEqual(record.exit_code, 0)
        self.assertTrue(record.duration_seconds >= 0.0)

        # Verify audit history in database
        history = self.sandbox.get_sandbox_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].audit_id, record.audit_id)

        # Verify administrative audit entry
        audit_log = self.db.get_audit_log(limit=5)
        actions = [a.action for a in audit_log]
        self.assertIn("SANDBOX_EXECUTION_COMPLETED", actions)

    def test_06_simulated_suspicious_behavior_detection(self):
        """Verify suspicious file modifications in containment trigger SUSPICIOUS/MALICIOUS verdict."""
        mock_suspicious_behavior = {
            "processes": ["suspicious_canary.exe"],
            "files": [r"C:\Users\Target\Documents\notes.lockbit"],
            "registry": [],
            "network_blocked": ["198.51.100.23:4444"],
            "exit_code": 0,
        }

        ok, msg, record = self.sandbox.execute_harmless_sample(
            sample_path=self.benign_sample,
            admin_token=self.admin_token,
            simulated_behavior=mock_suspicious_behavior,
        )
        self.assertTrue(ok)
        self.assertEqual(record.verdict, "MALICIOUS")
        self.assertIn("notes.lockbit", record.details["files_touched"][0])

    def test_07_timeout_enforcement(self):
        """Verify sample exceeding execution timeout is bounded and marked TIMEOUT."""
        # Create a sample that sleeps longer than timeout
        sleep_sample = self.temp_dir / "sleeping_sample.py"
        sleep_sample.write_text("import time\ntime.sleep(10.0)\n")

        ok, msg, record = self.sandbox.execute_harmless_sample(
            sample_path=sleep_sample,
            admin_token=self.admin_token,
            timeout_seconds=1.0,
        )
        self.assertTrue(ok)
        self.assertEqual(record.verdict, "TIMEOUT")
        self.assertEqual(record.exit_code, -9)

    def test_08_disposable_workspace_cleanup(self):
        """Verify temporary execution run directory is deleted after analysis."""
        ok, _, record = self.sandbox.execute_harmless_sample(
            sample_path=self.benign_sample,
            admin_token=self.admin_token,
        )
        self.assertTrue(ok)

        run_workspace = self.sandbox._runs_dir / record.audit_id
        # Workspace must be removed
        self.assertFalse(run_workspace.exists())


if __name__ == "__main__":
    unittest.main()

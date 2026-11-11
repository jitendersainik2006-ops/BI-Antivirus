"""
Unit and integration tests for Centralized Policy Engine, Enterprise Device Control,
and Enterprise Application Control with D: drive containment and Windows OS enforcement validation.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.core.policy_engine import (
    PolicyEngine,
    PolicyKeyManager,
    DEVICE_ACTION_ALLOW,
    DEVICE_ACTION_READ_ONLY,
    DEVICE_ACTION_BLOCK,
    APP_MODE_AUDIT,
    APP_MODE_ENFORCE,
)
from bi_antivirus.monitors.device_control import DeviceControlSentinel
from bi_antivirus.monitors.app_control import ApplicationControlSentinel
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.engine import AntivirusEngine

# Enforce all temporary test files strictly on D: drive
D_DRIVE_SCRATCH = Path(r"D:\bit defender\data\crypto_test_scratch")


class TestEnterprisePolicyAndControls(unittest.TestCase):
    """Test suite validating Enterprise Policy, Device Control, and Application Control."""

    def setUp(self):
        D_DRIVE_SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=str(D_DRIVE_SCRATCH), ignore_cleanup_errors=True)
        self.policy_file = Path(self.temp_dir.name) / "test_policy.json"
        self.db_file = Path(self.temp_dir.name) / "test_history.db"
        self.history_db = HistoryDatabase(db_path=self.db_file)
        self.policy_engine = PolicyEngine(policy_path=self.policy_file)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 1. Policy Engine Tests
    # ------------------------------------------------------------------

    def test_baseline_policy_initialization_and_signing(self):
        """Verify default policy creation, schema validation, and HMAC signature."""
        self.assertTrue(self.policy_file.exists())
        sig_file = self.policy_file.with_suffix(".sig")
        self.assertTrue(sig_file.exists())

        pol = self.policy_engine.current_policy
        self.assertEqual(pol.get("policy_name"), "Standard Enterprise Baseline")
        self.assertEqual(pol.get("policy_sequence"), 1)
        self.assertIn("device_control", pol)
        self.assertIn("application_control", pol)

        # Signature verification
        sig = sig_file.read_text().strip()
        computed = self.policy_engine.calculate_signature(pol)
        self.assertEqual(sig, computed)

    def test_policy_tamper_detection(self):
        """Verify that tampering with policy JSON triggers detection and safe fallback."""
        # Maliciously modify the policy file on disk without updating signature
        with open(self.policy_file, "r+", encoding="utf-8") as f:
            data = json.load(f)
            data["device_control"]["block_all_removable"] = True
            f.seek(0)
            json.dump(data, f)
            f.truncate()

        # Re-instantiating PolicyEngine must detect invalid HMAC and revert to baseline
        new_engine = PolicyEngine(policy_path=self.policy_file)
        # Baseline has block_all_removable == False
        self.assertFalse(new_engine.current_policy["device_control"]["block_all_removable"])

    def test_policy_rollback_protection(self):
        """Verify that anti-rollback protections increment sequence and prevent replay."""
        pol = self.policy_engine.current_policy
        self.assertEqual(pol.get("policy_sequence"), 1)

        # Attempt to submit update with same sequence: engine must auto-increment
        success, msg = self.policy_engine.update_policy(pol)
        self.assertTrue(success)
        self.assertEqual(self.policy_engine.current_policy["policy_sequence"], 2)

    def test_policy_update_and_listener(self):
        """Verify dynamic policy updates and registered listener notifications."""
        notifications = []
        self.policy_engine.register_listener(lambda p: notifications.append(p["policy_name"]))

        updated_pol = self.policy_engine.current_policy
        updated_pol["policy_name"] = "Hardened Government Profile"
        updated_pol["device_control"]["default_action"] = DEVICE_ACTION_READ_ONLY

        success, msg = self.policy_engine.update_policy(updated_pol)
        self.assertTrue(success)
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0], "Hardened Government Profile")
        self.assertEqual(self.policy_engine.current_policy["device_control"]["default_action"], DEVICE_ACTION_READ_ONLY)

    # ------------------------------------------------------------------
    # 2. Device Control Policy Evaluation & OS Enforcement
    # ------------------------------------------------------------------

    def test_device_policy_decisions(self):
        """Verify granular device control evaluation (Allow, Block, Read-Only, Whitelists)."""
        # 1. Default Allow
        action, _ = self.policy_engine.evaluate_device_policy(device_id="E:\\", serial_number="AA11-BB22")
        self.assertEqual(action, DEVICE_ACTION_ALLOW)

        # 2. Add Blacklist Rule
        pol = self.policy_engine.current_policy
        pol["device_control"]["blacklisted_devices"] = [
            {"serial_number": "BAD1-0001", "description": "Compromised USB"}
        ]
        self.policy_engine.update_policy(pol)

        action, reason = self.policy_engine.evaluate_device_policy(device_id="E:\\", serial_number="BAD1-0001")
        self.assertEqual(action, DEVICE_ACTION_BLOCK)
        self.assertIn("Compromised USB", reason)

        # 3. Add Whitelist Rule overriding Read-Only Unregistered
        pol["device_control"]["enforce_read_only_unregistered"] = True
        pol["device_control"]["whitelisted_devices"] = [
            {"serial_number": "CORP-9999", "description": "Encrypted Company Drive"}
        ]
        self.policy_engine.update_policy(pol)

        # Unregistered device gets READ_ONLY
        act_unreg, _ = self.policy_engine.evaluate_device_policy(device_id="E:\\", serial_number="RAND-5555")
        self.assertEqual(act_unreg, DEVICE_ACTION_READ_ONLY)

        # Whitelisted device gets ALLOW
        act_white, _ = self.policy_engine.evaluate_device_policy(device_id="E:\\", serial_number="CORP-9999")
        self.assertEqual(act_white, DEVICE_ACTION_ALLOW)

    def test_device_control_os_enforcement_methods(self):
        """Verify OS write-protect query and dismount method behavior."""
        # Query write-protect registry state (read-only query)
        wp_status = DeviceControlSentinel.query_os_write_protect()
        self.assertIn(wp_status, (True, False, None))

        # Safe dismount attempt on non-existent volume (must return False cleanly without crashing)
        ok, msg = DeviceControlSentinel.dismount_blocked_drive("Z:\\")
        self.assertFalse(ok)
        self.assertIn("Z:", msg)

    # ------------------------------------------------------------------
    # 3. Application Control Policy Evaluation & Enforcement
    # ------------------------------------------------------------------

    def test_application_control_hash_rules(self):
        """Verify SHA-256 binary hash whitelisting and blacklisting."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # Blacklisted Hash
        pol = self.policy_engine.current_policy
        pol["application_control"]["blacklisted_hashes"] = [test_hash]
        self.policy_engine.update_policy(pol)

        verdict, reason = self.policy_engine.evaluate_application_policy(
            file_path=r"C:\Tools\sample.exe",
            sha256_hash=test_hash,
        )
        self.assertEqual(verdict, "BLOCK")
        self.assertIn("explicitly blacklisted", reason)

        # Whitelisted Hash
        pol["application_control"]["blacklisted_hashes"] = []
        pol["application_control"]["whitelisted_hashes"] = [test_hash]
        self.policy_engine.update_policy(pol)

        verdict, reason = self.policy_engine.evaluate_application_policy(
            file_path=r"C:\Tools\sample.exe",
            sha256_hash=test_hash,
        )
        self.assertEqual(verdict, "ALLOW")
        self.assertIn("explicitly whitelisted", reason)

    def test_application_control_untrusted_directories(self):
        """Verify untrusted directory execution lockdown in AUDIT and ENFORCE modes."""
        # 1. Audit Mode (Warning only)
        pol = self.policy_engine.current_policy
        pol["application_control"]["mode"] = APP_MODE_AUDIT
        self.policy_engine.update_policy(pol)

        verdict, reason = self.policy_engine.evaluate_application_policy(
            file_path=r"C:\Users\User\AppData\Local\Temp\dropper.exe"
        )
        self.assertEqual(verdict, "AUDIT")
        self.assertIn("untrusted path", reason)

        # 2. Enforce Mode (Blocked)
        pol["application_control"]["mode"] = APP_MODE_ENFORCE
        self.policy_engine.update_policy(pol)

        verdict, reason = self.policy_engine.evaluate_application_policy(
            file_path=r"C:\Users\User\AppData\Local\Temp\dropper.exe"
        )
        self.assertEqual(verdict, "BLOCK")
        self.assertIn("untrusted path", reason)

    def test_application_control_critical_windows_exclusions(self):
        """Verify critical Windows processes in System32 are never blocked."""
        sentinel = ApplicationControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
        )
        res = sentinel.evaluate_executable(r"C:\Windows\System32\svchost.exe")
        self.assertEqual(res["status"], "ALLOW")
        self.assertIn("Critical Windows", res["reason"])

    def test_application_control_terminate_process_safety(self):
        """Verify self-termination and idle process termination guards."""
        sentinel = ApplicationControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
        )
        # Attempting to terminate self must be blocked
        ok, msg = sentinel.terminate_process(os.getpid())
        self.assertFalse(ok)
        self.assertIn("Cannot terminate self", msg)

        # Attempting to terminate PID 0/4 (system) must be blocked
        ok_sys, _ = sentinel.terminate_process(4)
        self.assertFalse(ok_sys)

    # ------------------------------------------------------------------
    # 4. DeviceControlSentinel & ApplicationControlSentinel Execution
    # ------------------------------------------------------------------

    def test_device_control_sentinel_audit(self):
        """Verify DeviceControlSentinel evaluates devices and writes audit records to DB."""
        sentinel = DeviceControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
        )
        report = sentinel.evaluate_and_enforce_device("F:\\")
        self.assertIn("policy_action", report)
        self.assertIn("os_enforced", report)
        self.assertEqual(len(sentinel.get_active_devices()), 1)

        # Verify event logged in database
        events = self.history_db.get_security_events(limit=5)
        self.assertTrue(any("DEVICE" in ev["event_type"] for ev in events))

    def test_application_control_sentinel_evaluation(self):
        """Verify ApplicationControlSentinel inspects physical files and caches results."""
        # Create a dummy test file in D: drive scratch
        test_file = Path(self.temp_dir.name) / "test_app.exe"
        test_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00TEST_PAYLOAD")

        sentinel = ApplicationControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
        )

        res = sentinel.evaluate_executable(str(test_file))
        self.assertIn("status", res)
        self.assertIsNotNone(res["sha256"])

        # Second call must hit cache
        res_cached = sentinel.evaluate_executable(str(test_file))
        self.assertTrue(res_cached.get("cached", False))

    # ------------------------------------------------------------------
    # 5. AntivirusEngine Coordinator Integration
    # ------------------------------------------------------------------

    def test_engine_policy_and_controls_integration(self):
        """Verify AntivirusEngine initializes PolicyEngine, DeviceControl, and ApplicationControl."""
        engine = AntivirusEngine()
        self.assertIsNotNone(engine.policy_engine)
        self.assertIsNotNone(engine.device_control)
        self.assertIsNotNone(engine.app_control)

        # Verify callback routes cleanly without error
        engine._on_device_control_event({
            "drive_path": "Z:\\",
            "policy_action": "ALLOW",
            "serial_number": "TEST-1234",
            "reason": "Test unit validation",
        })

        engine._on_app_control_violation({
            "file_path": r"C:\Temp\malware.exe",
            "file_name": "malware.exe",
            "status": "AUDIT",
            "reason": "Test unit audit violation",
            "sha256": "0123456789abcdef",
        })


if __name__ == "__main__":
    unittest.main()

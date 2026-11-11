"""
Sprint 13 Automated Test Suite: Enforcement Visibility & Windows ETW Telemetry Probe
Validates Administrator vs Standard User mode detection, feature restriction auditing,
Windows ETW provider discovery, permission gating, safe non-PII diagnostic logging,
and dashboard integration.
"""

import unittest
import sys
from pathlib import Path

from bi_antivirus.core.privilege_manager import PrivilegeManager, is_user_admin
from bi_antivirus.monitors.etw_telemetry import ETWTelemetryProbe, DEFENSIVE_ETW_PROVIDERS
from bi_antivirus.core.engine import AntivirusEngine


class TestSprint13VisibilityAndETW(unittest.TestCase):
    """Test suite for Sprint 13 enforcement visibility and ETW telemetry probe."""

    def test_01_privilege_detection_and_integrity_level(self):
        """Verify PrivilegeManager reports boolean is_admin, valid mode title, and integrity level."""
        details = PrivilegeManager.get_enforcement_details()

        self.assertIn("is_admin", details)
        self.assertIsInstance(details["is_admin"], bool)
        self.assertIn("mode_title", details)
        self.assertIn("integrity_level", details)
        self.assertIn("enforcement_mode", details)
        self.assertIn("status_color", details)
        self.assertIn("explanation", details)

        if details["is_admin"]:
            self.assertIn("Administrator", details["mode_title"])
            self.assertEqual(details["enforcement_mode"], "FULL_ENFORCEMENT")
            self.assertEqual(details["restricted_count"], 0)
        else:
            self.assertIn("Standard User", details["mode_title"])
            self.assertEqual(details["enforcement_mode"], "AUDIT_ONLY")
            self.assertGreaterEqual(details["restricted_count"], 4)

    def test_02_feature_enforcement_dictionary_and_restrictions(self):
        """Verify all core subsystems are mapped with enforcement state and elevation flag."""
        details = PrivilegeManager.get_enforcement_details()
        features = details["features"]

        expected_features = [
            "realtime_file_guard",
            "heuristic_and_ml",
            "quarantine_vault",
            "authenticode_verifier",
            "ransomware_honeypots",
            "firewall_orchestration",
            "usb_device_control",
            "bitlocker_management",
            "process_guard",
            "etw_telemetry",
        ]

        for fid in expected_features:
            self.assertIn(fid, features)
            f = features[fid]
            self.assertIn("name", f)
            self.assertIn("state", f)
            self.assertIn("enforcement", f)
            self.assertIn("requires_elevation", f)
            self.assertIsInstance(f["requires_elevation"], bool)

        # Elevation required features
        self.assertTrue(features["firewall_orchestration"]["requires_elevation"])
        self.assertTrue(features["usb_device_control"]["requires_elevation"])
        self.assertTrue(features["bitlocker_management"]["requires_elevation"])
        self.assertTrue(features["process_guard"]["requires_elevation"])

        # Non-elevation required features
        self.assertFalse(features["realtime_file_guard"]["requires_elevation"])
        self.assertFalse(features["heuristic_and_ml"]["requires_elevation"])
        self.assertFalse(features["quarantine_vault"]["requires_elevation"])
        self.assertFalse(features["authenticode_verifier"]["requires_elevation"])

    def test_03_etw_provider_discovery_and_registration(self):
        """Verify ETWTelemetryProbe discovers and caches defensive provider registrations."""
        probe = ETWTelemetryProbe(check_registry_on_init=False)
        self.assertEqual(probe.is_windows, sys.platform == "win32")

        status = probe.get_etw_status()
        self.assertIn("supported", status)
        self.assertIn("operational_status", status)
        self.assertIn("provider_count", status)
        self.assertEqual(status["provider_count"], len(DEFENSIVE_ETW_PROVIDERS))
        self.assertIn("providers", status)
        self.assertEqual(len(status["providers"]), len(DEFENSIVE_ETW_PROVIDERS))

        provider_names = [p["name"] for p in status["providers"]]
        self.assertIn("Microsoft-Windows-Kernel-Process", provider_names)
        self.assertIn("Microsoft-Windows-Threat-Intelligence", provider_names)
        self.assertIn("Microsoft-Windows-DNS-Client", provider_names)
        self.assertIn("Microsoft-Windows-Kernel-Network", provider_names)

    def test_04_etw_permission_and_fallback_graceful_handling(self):
        """Verify trace permission checking and seamless fallback to Toolhelp32 snapshotting."""
        probe = ETWTelemetryProbe(check_registry_on_init=False)
        can_trace = probe.can_start_kernel_trace()
        self.assertEqual(can_trace, is_user_admin() and probe.is_windows)

        status = probe.get_etw_status()
        self.assertTrue(status["fallback_active"])
        self.assertIn("Toolhelp32", status["fallback_mechanism"])
        self.assertIn("ReadDirectoryChangesW", status["fallback_mechanism"])

        # Operational status must reflect real permission state
        if can_trace:
            self.assertEqual(status["operational_status"], "PERMITTED_PROBE")
        else:
            self.assertEqual(status["operational_status"], "RESTRICTED_PERMISSIONS")

    def test_05_etw_sanitized_non_pii_diagnostic_events(self):
        """Verify diagnostic events strip personal information and bound buffer capacity."""
        probe = ETWTelemetryProbe(check_registry_on_init=False)
        self.assertEqual(len(probe._diagnostic_events), 0)

        # Record event with potential PII (full user paths, user names)
        probe.record_diagnostic_event("PROCESS_START", {
            "pid": 4040,
            "image": r"C:\Users\JohnDoe\AppData\Local\malware_poc.exe",
            "username": "secret_user",
            "command_line": "--token=SECRET_AUTH_TOKEN",
        })

        self.assertEqual(len(probe._diagnostic_events), 1)
        event = probe._diagnostic_events[0]
        self.assertEqual(event["event_type"], "PROCESS_START")
        self.assertEqual(event["pid"], 4040)
        # Verify base image name only (no user path or secret token)
        self.assertEqual(event["image"], "malware_poc.exe")
        self.assertNotIn("secret_user", str(event))
        self.assertNotIn("SECRET_AUTH_TOKEN", str(event))

        # Test buffer truncation ceiling
        for i in range(120):
            probe.record_diagnostic_event(f"EVENT_{i}", {"pid": i, "image": f"app_{i}.exe"})

        self.assertLessEqual(len(probe._diagnostic_events), probe._max_events)

    def test_06_engine_dashboard_integration(self):
        """Verify AntivirusEngine integrates privilege details and ETW status into telemetry summary."""
        engine = AntivirusEngine()
        self.assertIsNotNone(engine.privilege_manager)
        self.assertIsNotNone(engine.etw_probe)

        summary = engine.get_dashboard_summary()
        self.assertIn("enforcement_details", summary)
        self.assertIn("etw_status", summary)

        enf = summary["enforcement_details"]
        self.assertIn("mode_title", enf)
        self.assertIn("integrity_level", enf)

        etw = summary["etw_status"]
        self.assertIn("operational_status", etw)
        self.assertIn("fallback_active", etw)


if __name__ == "__main__":
    unittest.main()

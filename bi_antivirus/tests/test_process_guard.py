"""
BI Antivirus - Process Guard Security Sentinel Tests
Verifies:
- Token privilege inspection and SeDebugPrivilege / SeTcbPrivilege anomaly detection
- PPID spoofing detection: disallowed parents (lsass/csrss spawning terminals)
- PPID spoofing detection: creation time order inversion
- Critical handle auditing targeting LSASS with VM_READ / VM_WRITE / ALL_ACCESS
- Safe non-destructive operation and alert persistence
"""

import unittest
from bi_antivirus.monitors.process_guard import ProcessGuard, ProcessGuardAlert, DANGEROUS_LSASS_ACCESS_MASK, PROCESS_VM_READ, PROCESS_ALL_ACCESS


class TestProcessGuard(unittest.TestCase):
    """Test suite for Process Guard."""

    def setUp(self):
        self.guard = ProcessGuard()

    def test_01_token_audit_clean_process(self):
        """Verify normal process without elevated debug privileges triggers no alerts."""
        alerts = self.guard.audit_process_token(
            pid=1234,
            process_name="notepad.exe",
            image_path=r"C:\Windows\System32\notepad.exe",
            simulated_privileges=["SeChangeNotifyPrivilege"],
        )
        self.assertEqual(len(alerts), 0)

    def test_02_token_audit_sedebugprivilege_theft(self):
        """Verify non-system process holding SeDebugPrivilege triggers high severity alert."""
        alerts = self.guard.audit_process_token(
            pid=4567,
            process_name="powershell.exe",
            image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            simulated_privileges=["SeDebugPrivilege"],
        )
        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "TOKEN_PRIVILEGE_ANOMALY")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.mitre_technique, "T1134.001")

    def test_03_ppid_spoofing_disallowed_parent(self):
        """Verify cmd.exe reporting lsass.exe as parent triggers critical alert."""
        alerts = self.guard.audit_ppid_spoofing(
            pid=9999,
            ppid=600,
            process_name="cmd.exe",
            parent_name="lsass.exe",
        )
        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "PPID_SPOOFING_DISALLOWED_PARENT")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.mitre_technique, "T1134.004")

    def test_04_ppid_spoofing_creation_time_inversion(self):
        """Verify child created earlier than parent triggers time inversion alert."""
        # Child timestamp 100.0, parent timestamp 200.0 (child exists before parent was born)
        alerts = self.guard.audit_ppid_spoofing(
            pid=8888,
            ppid=4444,
            process_name="svchost.exe",
            parent_name="services.exe",
            create_time=100.0,
            parent_create_time=200.0,
        )
        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "PPID_SPOOFING_TIME_INVERSION")
        self.assertEqual(alert.severity, "HIGH")

    def test_05_critical_handle_theft_lsass(self):
        """Verify unauthorized memory read handle targeting lsass.exe triggers critical alert."""
        alert = self.guard.audit_critical_handle(
            source_pid=5555,
            source_name="untrusted_scanner.exe",
            target_pid=600,
            target_name="lsass.exe",
            desired_access=PROCESS_VM_READ,
        )
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "CRITICAL_HANDLE_THEFT_ATTEMPT")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.mitre_technique, "T1003.001")

    def test_06_critical_handle_legitimate_system_service_allowed(self):
        """Verify legitimate Windows core components opening handles on LSASS are not flagged."""
        alert = self.guard.audit_critical_handle(
            source_pid=500,
            source_name="services.exe",
            target_pid=600,
            target_name="lsass.exe",
            desired_access=PROCESS_ALL_ACCESS,
        )
        self.assertIsNone(alert)

    def test_07_process_guard_metrics(self):
        """Verify guard diagnostics and alert counting."""
        status = self.guard.get_guard_status()
        self.assertIn("alerts_total", status)
        self.assertIn("critical_alerts", status)


if __name__ == "__main__":
    unittest.main()

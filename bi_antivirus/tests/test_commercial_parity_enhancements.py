"""
Unit tests for BI Antivirus Commercial Feature Parity Enhancements.
Tests genuine Windows API integrations, Zone.Identifier ADS ingestion,
Toolhelp32 lifecycle tracking, USBSTOR registry enumeration, BadUSB/LNK heuristics,
Firewall EDR isolation, TPM 2.0 telemetry, and WebProtection Punycode/DGA heuristics.
All tests use harmless synthetic data and clean-room mocks.
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from bi_antivirus.monitors.realtime import RealTimeGuard
from bi_antivirus.monitors.exploit_shield import MemoryExploitShield
from bi_antivirus.monitors.usb_sentinel import USBSentinel
from bi_antivirus.monitors.device_control import DeviceControlSentinel
from bi_antivirus.monitors.firewall_monitor import FirewallMonitor
from bi_antivirus.monitors.encryption_manager import DiskEncryptionSentinel
from bi_antivirus.monitors.etw_telemetry import ETWTelemetryProbe
from bi_antivirus.monitors.web_protection import WebProtection
from bi_antivirus.database.history import HistoryDatabase

TEST_SCRATCH_DIR = Path(r"D:\bit defender\data\parity_test_scratch")


class TestCommercialParityEnhancements(unittest.TestCase):
    """Test suite for commercial feature parity enhancements across defensive monitors."""

    def setUp(self):
        TEST_SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=str(TEST_SCRATCH_DIR), ignore_cleanup_errors=True)
        self.test_root = Path(self.temp_dir.name)
        self.history_db = HistoryDatabase(db_path=self.test_root / "test_history.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. RealTimeGuard: Zone.Identifier ADS & Elevated ML Scrutiny
    # -------------------------------------------------------------------------
    def test_01_read_zone_identifier_ads(self):
        """Verify Zone.Identifier parsing on Windows NTFS Alternate Data Streams."""
        sample_file = self.test_root / "downloaded_script.ps1"
        sample_file.write_text("Write-Host 'Test Payload'", encoding="utf-8")

        ads_text = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://malicious-distribution.example/payload.ps1\r\nReferrerUrl=https://attacker.example\r\n"
        
        # Patch the ads_path exists and read_text
        with patch("pathlib.Path.exists", return_value=True), patch("pathlib.Path.read_text", return_value=ads_text):
            meta = RealTimeGuard.read_zone_identifier(sample_file)
            self.assertIsNotNone(meta)
            self.assertEqual(meta["zone_id"], 3)
            self.assertTrue(meta["is_untrusted"])
            self.assertIn("malicious-distribution.example", meta["host_url"])
            self.assertIn("attacker.example", meta["referrer_url"])

    def test_02_realtime_guard_win32_watcher_reporting(self):
        """Verify RealTimeGuard reports Win32 watcher status and metrics."""
        guard = RealTimeGuard(history_db=self.history_db)
        status = guard.get_guard_status()
        self.assertIn("win32_watchers_active", status)

        health = guard.get_health_status()
        self.assertIn("win32_watchers_active", health)

    # -------------------------------------------------------------------------
    # 2. MemoryExploitShield: Toolhelp32 Enumeration & Unbacked PE Headers
    # -------------------------------------------------------------------------
    def test_03_exploit_shield_toolhelp_enumeration(self):
        """Verify ExploitShield enumerates running processes via Toolhelp32 snapshot."""
        procs = MemoryExploitShield._enumerate_processes_toolhelp()
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)
        current_pid = os.getpid()
        pids = [p[0] for p in procs]
        self.assertIn(current_pid, pids)

    def test_04_exploit_shield_audit_live_process(self):
        """Verify audit_process runs memory region sweep on current process."""
        shield = MemoryExploitShield(history_db=self.history_db)
        res = shield.audit_process(os.getpid(), "python.exe")
        self.assertIsInstance(res, dict)
        self.assertEqual(res["pid"], os.getpid())
        self.assertIn("rwx_regions_count", res)
        self.assertIn("unbacked_executable_count", res)
        self.assertIn("dep", res)
        self.assertIn("aslr", res)

    # -------------------------------------------------------------------------
    # 3. USBSentinel: USBSTOR Hardware Enumeration & BadUSB/LNK Heuristics
    # -------------------------------------------------------------------------
    def test_05_usb_hardware_devices_usbstor(self):
        """Verify USB hardware discovery extracts vendor and product from USBSTOR registry."""
        devices = USBSentinel.get_usb_hardware_devices()
        self.assertIsInstance(devices, list)
        for dev in devices:
            self.assertIn("hardware_id", dev)
            self.assertIn("serial_number", dev)

    def test_06_usb_badusb_ducky_script_detection(self):
        """Verify USBSentinel detects BadUSB and Rubber Ducky script payloads."""
        ducky_file = self.test_root / "inject.bin"
        ducky_file.write_bytes(b"\x00\x14\x00\x00\x00\x08")

        script_file = self.test_root / "payload.dd"
        script_file.write_text("REM Rubber Ducky Script\nDELAY 1000\nSTRING powershell -enc\nENTER\n", encoding="utf-8")

        audit_res = USBSentinel.audit_drive_root(str(self.test_root))
        self.assertTrue(audit_res["is_threat"])
        threats = audit_res["threats"]
        self.assertGreater(len(threats), 0)
        threat_names = [t["threat_name"] for t in threats]
        self.assertTrue(any("BadUSB" in name or "DuckyScript" in name for name in threat_names))

    def test_07_usb_malicious_lnk_embedded_interpreter(self):
        """Verify USBSentinel flags malicious .lnk shortcuts containing powershell/cmd execution."""
        lnk_file = self.test_root / "Documents_Invoice.lnk"
        fake_lnk_content = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 30 + b"powershell.exe -w hidden -enc JAB"
        lnk_file.write_bytes(fake_lnk_content)

        audit_res = USBSentinel.audit_drive_root(str(self.test_root))
        threats = audit_res["threats"]
        lnk_threats = [t for t in threats if "LNK" in t["threat_name"]]
        self.assertEqual(len(lnk_threats), 1)
        self.assertIn("embedded command interpreter", lnk_threats[0]["description"])

    # -------------------------------------------------------------------------
    # 4. FirewallMonitor: EDR Host Isolation & Dangerous Port Auditing
    # -------------------------------------------------------------------------
    def test_08_firewall_host_isolation_safety_checks(self):
        """Verify isolate_host requires valid admin_token and rejects invalid tokens."""
        # Unauthorized token must fail
        res = FirewallMonitor.isolate_host(allowed_ips=["192.168.1.100"], admin_token="WRONG_TOKEN")
        self.assertFalse(res["success"])
        self.assertIn("UNAUTHORIZED", res["error"])

        # Mock netsh commands for safe verification
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout="Ok.")
            ok_res = FirewallMonitor.isolate_host(allowed_ips=["192.168.1.50"], admin_token="BI-SEC-ADMIN-ROOT-2026")
            self.assertTrue(ok_res["success"])
            self.assertEqual(ok_res["status"], "ISOLATED")

            # Test unisolate
            un_res = FirewallMonitor.unisolate_host(admin_token="BI-SEC-ADMIN-ROOT-2026")
            self.assertTrue(un_res["success"])
            self.assertEqual(un_res["status"], "UNISOLATED")

    def test_09_firewall_dangerous_rule_auditing(self):
        """Verify audit_dangerous_firewall_rules parses exposed SMB, RDP, and WinRM."""
        mock_rules = (
            "Rule Name:                            Open SMB\n"
            "Enabled:                              Yes\n"
            "Direction:                            In\n"
            "Action:                               Allow\n"
            "LocalPort:                            445\n\n"
            "Rule Name:                            Open RDP\n"
            "Enabled:                              Yes\n"
            "Direction:                            In\n"
            "Action:                               Allow\n"
            "LocalPort:                            3389\n"
        )
        with patch("subprocess.check_output", return_value=mock_rules):
            findings = FirewallMonitor.audit_dangerous_firewall_rules()
            self.assertIsInstance(findings, list)
            self.assertGreater(len(findings), 0)
            risks = [f["risk"] for f in findings]
            self.assertTrue(any("445" in r for r in risks))
            self.assertTrue(any("3389" in r for r in risks))

    # -------------------------------------------------------------------------
    # 5. DiskEncryptionSentinel: TPM 2.0 Posture & OS Edition Auditing
    # -------------------------------------------------------------------------
    def test_10_disk_encryption_tpm_and_os_edition(self):
        """Verify DiskEncryptionSentinel queries TPM chip and Windows Edition."""
        sentinel = DiskEncryptionSentinel(history_db=self.history_db)
        audit = sentinel.run_compliance_audit()
        
        self.assertIn("windows_edition", audit)
        self.assertIn("tpm_posture", audit)
        self.assertIn("volumes", audit)

        tpm = sentinel.get_tpm_status()
        self.assertIn("tpm_present", tpm)
        self.assertIn("spec_version", tpm)

        os_edition = sentinel.get_os_edition()
        self.assertIn("edition_id", os_edition)
        self.assertIn("bitlocker_supported", os_edition)

    # -------------------------------------------------------------------------
    # 6. ETWTelemetryProbe: Toolhelp32 Lifecycle Tracker & Trace Discovery
    # -------------------------------------------------------------------------
    def test_11_etw_telemetry_lifecycle_differential(self):
        """Verify ETWTelemetryProbe differential engine captures process lifecycle events."""
        probe = ETWTelemetryProbe(check_registry_on_init=True)
        status = probe.get_etw_status()
        
        self.assertTrue(status["fallback_active"])
        self.assertIn("Toolhelp32", status["fallback_mechanism"])
        self.assertGreater(status["fallback_snapshot_pids_tracked"], 0)
        self.assertIsInstance(status["active_trace_sessions"], list)

        # Test snapshot capture
        snap = probe.capture_process_snapshot()
        self.assertIsInstance(snap, dict)
        self.assertIn(os.getpid(), snap)

        # Poll lifecycle events
        events = probe.poll_process_lifecycle_events()
        self.assertIsInstance(events, list)

    # -------------------------------------------------------------------------
    # 7. WebProtection: Punycode Homograph & DGA Domain Heuristics
    # -------------------------------------------------------------------------
    def test_12_web_protection_punycode_and_dga(self):
        """Verify WebProtection detects IDN Punycode spoofing and high-entropy DGA domains."""
        wp = WebProtection()
        
        # Punycode spoofing
        puny_res = wp.check_url("https://xn--pple-43d.com/login")
        self.assertTrue(puny_res["is_threat"])
        self.assertIn("Punycode", puny_res["reason"])

        # DGA domain detection
        dga_res = wp.check_url("http://xrkqwtzplmnhgb.biz/beacon")
        self.assertTrue(dga_res["is_threat"] or dga_res.get("risk_score", 0) >= 35)

        # Hosts file sinkhole audit
        hosts_audit = WebProtection.audit_hosts_file_sinkholes()
        self.assertIn("hosts_file_found", hosts_audit)
        self.assertIn("sinkhole_count", hosts_audit)


if __name__ == "__main__":
    unittest.main(verbosity=2)

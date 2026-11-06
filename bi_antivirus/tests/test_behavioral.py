"""
Test Suite: Behavioral Process Monitor & Threat Rules
"""

import unittest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.monitors.behavioral import BehavioralMonitor

class TestBehavioralMonitor(unittest.TestCase):

    def test_anomalous_parent_child_detection(self):
        # Test simulated Word spawning PowerShell
        proc = {
            "name": "powershell.exe",
            "pid": "1337",
            "command_line": "",
            "title": "",
        }
        res = BehavioralMonitor.evaluate_process_behavior(proc, parent_name="winword.exe")
        self.assertTrue(res["is_anomaly"])
        self.assertGreaterEqual(res["risk_score"], 75)
        self.assertEqual(res["severity"], "HIGH")
        self.assertTrue(any("AnomalousParentChild" in ind for ind in res["indicators"]))

    def test_ransomware_shadow_copy_deletion_cli(self):
        # Test vssadmin delete shadows command line
        proc = {
            "name": "vssadmin.exe",
            "pid": "4096",
            "command_line": "vssadmin delete shadows /all /quiet",
            "title": "",
        }
        res = BehavioralMonitor.evaluate_process_behavior(proc)
        self.assertTrue(res["is_anomaly"])
        self.assertTrue(any("Ransomware.ShadowCopyDeletion" in ind for ind in res["indicators"]))

    def test_clean_process_behavior(self):
        # Test clean explorer or browser process
        proc = {
            "name": "explorer.exe",
            "pid": "500",
            "command_line": "C:\\Windows\\explorer.exe",
            "title": "File Explorer",
        }
        res = BehavioralMonitor.evaluate_process_behavior(proc, parent_name="userinit.exe")
        self.assertFalse(res["is_anomaly"])
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["severity"], "CLEAN")

    def test_live_process_snapshot_and_cmdline_visibility(self):
        # Live Windows Toolhelp snapshot + NtQueryInformationProcess command line test
        import os
        snapshots = BehavioralMonitor.get_process_snapshot()
        self.assertGreater(len(snapshots), 0, "Process snapshot must return running processes")
        
        current_pid = str(os.getpid())
        my_proc = next((p for p in snapshots if p["pid"] == current_pid), None)
        self.assertIsNotNone(my_proc, f"Current PID {current_pid} must be in snapshot")
        self.assertIn("python", my_proc["name"].lower())
        self.assertTrue(len(my_proc["command_line"]) > 0, "Command line must be extracted for current process")
        self.assertIn("python", my_proc["command_line"].lower())


if __name__ == "__main__":
    unittest.main()

"""
BI Antivirus - Advanced EDR Telemetry & Correlation Tests
Verifies:
- Normalized telemetry event construction and schema validation
- MITRE ATT&CK matrix tagging across all 14 tactics
- Dynamic explainable risk scoring (0-100)
- Root-cause analysis (RCA) backtracking and process tree generation
- Automated response recommendations generator
- Multi-endpoint cross correlation for shared hashes and C2 IPs
"""

import unittest
from bi_antivirus.core.edr_engine import EDREngine, TelemetryEvent, MITRE_TACTICS_CATALOG


class TestAdvancedEDR(unittest.TestCase):
    """Test suite for Advanced EDR Engine."""

    def setUp(self):
        self.edr = EDREngine()

    def test_01_mitre_14_tactics_catalog_complete(self):
        """Verify all 14 MITRE tactics from TA0001 to TA0043 are present."""
        self.assertEqual(len(MITRE_TACTICS_CATALOG), 14)
        self.assertIn("TA0001", MITRE_TACTICS_CATALOG)  # Initial Access
        self.assertIn("TA0002", MITRE_TACTICS_CATALOG)  # Execution
        self.assertIn("TA0006", MITRE_TACTICS_CATALOG)  # Credential Access
        self.assertIn("TA0011", MITRE_TACTICS_CATALOG)  # Command and Control
        self.assertIn("TA0040", MITRE_TACTICS_CATALOG)  # Impact
        self.assertIn("TA0043", MITRE_TACTICS_CATALOG)  # Reconnaissance

    def test_02_event_normalization_and_mitre_tagging(self):
        """Verify TelemetryEvent correctly tags MITRE tactics and techniques from behavioral tags."""
        ev = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=2040,
            process_name="powershell.exe",
            ppid=1020,
            parent_process_name="cmd.exe",
            command_line="powershell.exe -enc SQBFAFgA...",
            behavior_tag="PROCESS_SPAWN_POWERSHELL_ENCODED",
        )
        self.assertEqual(ev.process_name, "powershell.exe")
        self.assertIn("Execution (TA0002)", ev.mitre_tactics)
        self.assertTrue(any("T1059.001" in t for t in ev.mitre_techniques))
        self.assertGreater(ev.risk_score, 0.0)

    def test_03_incident_correlation_and_risk_scoring(self):
        """Verify grouping multi-stage events computes combined explainable risk score."""
        ev1 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=1000,
            process_name="WINWORD.EXE",
            behavior_tag="PROCESS_SPAWN_CMD_CHILD_OF_OFFICE",
        )
        ev2 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=2000,
            process_name="cmd.exe",
            ppid=1000,
            parent_process_name="WINWORD.EXE",
            behavior_tag="PROCESS_SPAWN_POWERSHELL_ENCODED",
        )
        ev3 = self.edr.normalize_event(
            event_type="MEMORY_INJECT",
            pid=3000,
            process_name="powershell.exe",
            ppid=2000,
            parent_process_name="cmd.exe",
            behavior_tag="CREDENTIAL_DUMP_LSASS_ACCESS",
        )

        incident = self.edr.correlate_incident([ev1, ev2, ev3])
        self.assertEqual(incident.severity, "CRITICAL")
        self.assertGreaterEqual(incident.risk_score, 80.0)
        self.assertIn("ISOLATE_HOST: Immediately isolate endpoint from local network via BI Firewall.", incident.response_recommendations)
        self.assertIn("REVOKE_CREDENTIALS: Force immediate password reset and invalidate active Kerberos tickets.", incident.response_recommendations)

    def test_04_root_cause_analysis_backtracking(self):
        """Verify RCA correctly identifies initial ingress vector from parent chain."""
        ev1 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=1111,
            process_name="EXCEL.EXE",
            behavior_tag="PROCESS_SPAWN_CMD_CHILD_OF_OFFICE",
        )
        ev2 = self.edr.normalize_event(
            event_type="FILE_WRITE",
            pid=2222,
            process_name="cmd.exe",
            ppid=1111,
            parent_process_name="EXCEL.EXE",
            target_path=r"C:\Users\victim\AppData\Local\Temp\dropper.exe",
        )

        incident = self.edr.correlate_incident([ev1, ev2])
        rca = incident.root_cause_analysis
        self.assertEqual(rca["root_process_name"], "EXCEL.EXE")
        self.assertEqual(rca["probable_ingress_vector"], "MALICIOUS_DOCUMENT_OR_EMAIL")

    def test_05_cross_endpoint_correlation(self):
        """Verify correlation across distinct endpoint event streams for identical C2 IP and file hash."""
        ev_host1 = [
            TelemetryEvent(endpoint_id="HOST-FINANCE-01", hash="abc123sha256", remote_ip="203.0.113.88"),
        ]
        ev_host2 = [
            TelemetryEvent(endpoint_id="HOST-HR-04", hash="abc123sha256", remote_ip="203.0.113.88"),
        ]

        streams = {
            "HOST-FINANCE-01": ev_host1,
            "HOST-HR-04": ev_host2,
        }

        correlations = self.edr.cross_endpoint_correlation(streams)
        self.assertGreaterEqual(len(correlations), 2)
        corr_types = [c["correlation_type"] for c in correlations]
        self.assertIn("SHARED_MALICIOUS_HASH", corr_types)
        self.assertIn("SHARED_C2_COMMUNICATION", corr_types)


if __name__ == "__main__":
    unittest.main()

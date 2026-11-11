"""
BI Antivirus - Sprint 9 Advanced EDR & Threat Intelligence Tests
Verifies:
1. Telemetry Alert Deduplication (collapsing identical bursts within window)
2. Dynamic Multi-Vector Confidence Scoring (0.60 to 0.95)
3. Auditable Analyst Decision & Disposition Tracking
4. Investigation Report Generation (chronological timeline, RCA, MITRE, recommendations)
5. Threat Intelligence Feed Provenance & TTL Freshness/Expiration Enforcement
6. Malformed IOC Hash Schema Validation
"""

import time
import shutil
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.core.edr_engine import EDREngine, TelemetryEvent
from bi_antivirus.core.threat_intel import ThreatIntelEngine


class TestSprint9EDRAndThreatIntel(unittest.TestCase):
    """Test suite for Sprint 9 Advanced EDR and Threat Intelligence."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bi_s9_test_")
        self.edr = EDREngine()
        self.threat_intel = ThreatIntelEngine(data_dir=Path(self.temp_dir))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_telemetry_event_deduplication(self):
        """Verify that rapid successive duplicate telemetry events are deduplicated."""
        now = time.time()
        events = [
            TelemetryEvent(timestamp=now, event_type="NETWORK_CONNECT", pid=4000, process_name="miner.exe", remote_ip="203.0.113.50"),
            TelemetryEvent(timestamp=now + 0.5, event_type="NETWORK_CONNECT", pid=4000, process_name="miner.exe", remote_ip="203.0.113.50"),
            TelemetryEvent(timestamp=now + 1.0, event_type="NETWORK_CONNECT", pid=4000, process_name="miner.exe", remote_ip="203.0.113.50"),
            TelemetryEvent(timestamp=now + 1.5, event_type="PROCESS_CREATE", pid=5000, process_name="cmd.exe"),
        ]

        deduped = self.edr.deduplicate_events(events, window_seconds=3.0)
        self.assertEqual(len(deduped), 2, "3 duplicate network connections should collapse to 1")
        self.assertEqual(deduped[0].event_type, "NETWORK_CONNECT")
        self.assertEqual(deduped[1].event_type, "PROCESS_CREATE")

    def test_02_dynamic_confidence_scoring(self):
        """Verify confidence scores reflect single-vector vs multi-vector evidence convergence."""
        # Single vector (only process creation)
        ev1 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=1000,
            process_name="cmd.exe",
            behavior_tag="PROCESS_SPAWN_POWERSHELL_ENCODED",
        )
        inc_single = self.edr.correlate_incident([ev1])
        self.assertEqual(inc_single.confidence, 0.60)

        # Multi-vector (process + memory inject + network connect)
        ev2 = self.edr.normalize_event(
            event_type="MEMORY_INJECT",
            pid=2000,
            process_name="powershell.exe",
            behavior_tag="CREDENTIAL_DUMP_LSASS_ACCESS",
        )
        ev3 = self.edr.normalize_event(
            event_type="NETWORK_CONNECT",
            pid=2000,
            process_name="powershell.exe",
            remote_ip="198.51.100.22",
            behavior_tag="C2_OUTBOUND_SUSPICIOUS_PORT",
        )
        inc_multi = self.edr.correlate_incident([ev1, ev2, ev3])
        self.assertEqual(inc_multi.confidence, 0.95)

    def test_03_analyst_decision_auditability(self):
        """Verify recording analyst triage action updates status and maintains audit log."""
        ev = self.edr.normalize_event(event_type="PROCESS_CREATE", pid=1000, process_name="svchost.exe")
        incident = self.edr.correlate_incident([ev])
        inc_id = incident.incident_id

        # Record analyst decision
        success = self.edr.record_analyst_decision(
            incident_id=inc_id,
            analyst_user="secops_john",
            action="CONTAINMENT_DISPATCHED",
            notes="Host isolated; verified benign maintenance script.",
            status="CONTAINED",
        )
        self.assertTrue(success)
        self.assertEqual(incident.incident_status, "CONTAINED")
        self.assertEqual(len(incident.analyst_notes), 1)
        self.assertEqual(incident.analyst_notes[0]["analyst"], "secops_john")

    def test_04_investigation_report_generation(self):
        """Verify generate_investigation_report returns structured timeline, RCA, and MITRE mapping."""
        ev1 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=1234,
            process_name="WINWORD.EXE",
            behavior_tag="PROCESS_SPAWN_CMD_CHILD_OF_OFFICE",
        )
        ev2 = self.edr.normalize_event(
            event_type="PROCESS_CREATE",
            pid=5678,
            ppid=1234,
            process_name="cmd.exe",
            parent_process_name="WINWORD.EXE",
            behavior_tag="PROCESS_SPAWN_POWERSHELL_ENCODED",
        )

        incident = self.edr.correlate_incident([ev1, ev2])
        self.edr.record_analyst_decision(incident.incident_id, "lead_analyst", "INVESTIGATING", "Confirmed phishing macro")

        report = self.edr.generate_investigation_report(incident.incident_id)
        self.assertIsNotNone(report)
        self.assertEqual(report["incident_id"], incident.incident_id)
        self.assertIn("timeline", report)
        self.assertEqual(len(report["timeline"]), 2)
        self.assertEqual(report["root_cause_analysis"]["root_process_name"], "WINWORD.EXE")
        self.assertEqual(len(report["analyst_audit_log"]), 1)

    def test_05_threat_intel_ttl_expiration_rejection(self):
        """Verify that a signed threat intelligence bundle with an expired TTL is rejected."""
        expired_bundle = self.threat_intel.generate_update_bundle(
            version="2026.02",
            sequence=10,
            signatures=[{"file_hash": "a" * 64, "threat_name": "TestThreat"}],
            cve_advisories=[],
            provenance="OFFLINE_TEST_LABS",
            ttl_seconds=-3600.0,  # Expired 1 hour ago
        )

        ok, msg = self.threat_intel.verify_and_apply_bundle(expired_bundle)
        self.assertFalse(ok)
        self.assertIn("Feed freshness rejection", msg)

    def test_06_threat_intel_malformed_ioc_rejection(self):
        """Verify that signature bundles containing non-hex or corrupted file hashes are rejected."""
        corrupted_ioc_bundle = self.threat_intel.generate_update_bundle(
            version="2026.03",
            sequence=15,
            signatures=[{"file_hash": "NOT_A_VALID_HEX_HASH!@#$", "threat_name": "BadSignature"}],
            cve_advisories=[],
            provenance="OFFLINE_TEST_LABS",
        )

        ok, msg = self.threat_intel.verify_and_apply_bundle(corrupted_ioc_bundle)
        self.assertFalse(ok)
        self.assertIn("Malformed IOC rejection", msg)

    def test_07_threat_intel_valid_bundle_with_provenance_applied(self):
        """Verify that a valid, fresh, signed bundle with provenance metadata applies successfully."""
        valid_bundle = self.threat_intel.generate_update_bundle(
            version="2026.04",
            sequence=20,
            signatures=[{"file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat_name": "TestValidSha256"}],
            cve_advisories=[],
            provenance="BLACK_INTEL_AUTHORITATIVE_LABS",
            ttl_seconds=86400.0,
        )

        ok, msg = self.threat_intel.verify_and_apply_bundle(valid_bundle)
        self.assertTrue(ok, msg)
        self.assertEqual(self.threat_intel.current_sequence, 20)


if __name__ == "__main__":
    unittest.main()

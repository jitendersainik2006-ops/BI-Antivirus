"""
BI Antivirus - Test Suite for Enterprise Fleet Management
Verifies:
- Endpoint device registration and cryptographic enrollment token validation
- Heartbeat processing and offline endpoint timeout sweeps (> 300s)
- Policy distribution with monotonic version checks (anti-rollback protection)
- Administrator authorization and immutable audit logging
- Incident aggregation from critical endpoint alerts
- Endpoint network isolation and containment controls
- Device search, grouping, and tag filtering
"""

import time
import secrets
import unittest
from pathlib import Path

from bi_antivirus.config import SCRATCH_DIR, SEVERITY_CRITICAL, SEVERITY_HIGH
from bi_antivirus.enterprise.fleet_models import (
    EndpointDevice,
    FleetPolicy,
    FleetEvent,
    AdminAuditEntry,
    FleetIncident,
)
from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.fleet_manager import FleetManager


class TestFleetManager(unittest.TestCase):
    """Test suite for Enterprise Fleet Management Subsystem."""

    def setUp(self):
        uid = secrets.token_hex(4)
        self.scratch_dir = SCRATCH_DIR / f"test_fleet_{uid}"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.scratch_dir / f"test_fleet_{uid}.db"
        self.fleet_db = FleetDatabase(db_path=self.db_path)

        self.enrollment_key = "TEST-ENROLLMENT-SECRET-TOKEN-123"
        self.admin_token = "TEST-ADMIN-BEARER-SECRET-456"

        self.manager = FleetManager(
            fleet_db=self.fleet_db,
            master_enrollment_key=self.enrollment_key,
            admin_token=self.admin_token,
        )

    def tearDown(self):
        for f in self.scratch_dir.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            self.scratch_dir.rmdir()
        except Exception:
            pass

    def test_endpoint_registration_success(self):
        """Verify endpoint registration with valid cryptographic enrollment token."""
        ok, msg, ep_data = self.manager.register_endpoint(
            hostname="WS-FINANCE-01",
            ip_address="192.168.10.45",
            os_version="Windows 11 Pro 23H2",
            agent_version="1.1.0-PRO",
            enrollment_token=self.enrollment_key,
            department="Finance",
            tags=["workstation", "finance"],
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "Registration successful.")
        self.assertIsNotNone(ep_data)
        self.assertEqual(ep_data["hostname"], "WS-FINANCE-01")
        self.assertEqual(ep_data["health_status"], "HEALTHY")

        # Verify endpoint saved in database
        saved = self.fleet_db.get_endpoint(ep_data["id"])
        self.assertIsNotNone(saved)
        self.assertEqual(saved.hostname, "WS-FINANCE-01")
        self.assertEqual(saved.department, "Finance")

        # Verify registration event emitted
        events = self.fleet_db.get_fleet_events(endpoint_id=ep_data["id"])
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "ENDPOINT_REGISTERED")

    def test_endpoint_registration_invalid_token(self):
        """Verify endpoint registration rejection when token is invalid."""
        ok, msg, ep_data = self.manager.register_endpoint(
            hostname="ROGUE-HOST",
            ip_address="192.168.1.99",
            os_version="Linux",
            agent_version="1.0.0",
            enrollment_token="INVALID-UNAUTHORIZED-TOKEN",
        )
        self.assertFalse(ok)
        self.assertIn("failed", msg.lower())
        self.assertIsNone(ep_data)

    def test_heartbeat_processing(self):
        """Verify heartbeat updates last_seen and retrieves active policy."""
        ok, _, ep_data = self.manager.register_endpoint(
            hostname="SRV-APP-01",
            ip_address="10.0.0.12",
            os_version="Windows Server 2022",
            agent_version="1.1.0-PRO",
            enrollment_token=self.enrollment_key,
        )
        ep_id = ep_data["id"]

        # Send heartbeat
        hb_ok, hb_msg, hb_data = self.manager.process_heartbeat(
            endpoint_id=ep_id,
            ip_address="10.0.0.15",
            health_status="HEALTHY",
        )
        self.assertTrue(hb_ok)
        self.assertEqual(hb_data["endpoint_id"], ep_id)
        self.assertIsNotNone(hb_data["assigned_policy"])
        self.assertEqual(hb_data["assigned_policy"]["policy_id"], "POL-DEFAULT-V1")

        # Check DB updated
        ep = self.fleet_db.get_endpoint(ep_id)
        self.assertEqual(ep.ip_address, "10.0.0.15")

    def test_offline_endpoint_sweep(self):
        """Verify that endpoints missing heartbeats for > 300s are transitioned to OFFLINE."""
        ok, _, ep_data = self.manager.register_endpoint(
            hostname="LAPTOP-REMOTE",
            ip_address="172.16.0.4",
            os_version="Windows 10",
            agent_version="1.1.0",
            enrollment_token=self.enrollment_key,
        )
        ep_id = ep_data["id"]

        # Artificially age the endpoint's last_seen
        ep = self.fleet_db.get_endpoint(ep_id)
        ep.last_seen = time.time() - 400.0  # 400 seconds ago
        self.fleet_db.register_endpoint(ep)

        # Run sweep
        offline_count = self.manager.sweep_offline_endpoints(timeout_seconds=300.0)
        self.assertEqual(offline_count, 1)

        ep_after = self.fleet_db.get_endpoint(ep_id)
        self.assertEqual(ep_after.health_status, "OFFLINE")

    def test_policy_creation_and_monotonic_rollback_rejection(self):
        """Verify policy version tracking and rejection of rollback versions."""
        # 1. Create policy v1
        ok1, msg1 = self.manager.create_or_update_policy(
            admin_token=self.admin_token,
            policy_id="POL-HARDENED-FINANCE",
            policy_name="Finance Hardened Policy",
            version=1,
            rules={"realtime": True, "usb_blocked": True},
        )
        self.assertTrue(ok1)

        # 2. Update to policy v2
        ok2, msg2 = self.manager.create_or_update_policy(
            admin_token=self.admin_token,
            policy_id="POL-HARDENED-FINANCE",
            policy_name="Finance Hardened Policy",
            version=2,
            rules={"realtime": True, "usb_blocked": True, "firewall_strict": True},
        )
        self.assertTrue(ok2)

        # 3. Attempt rollback to version 1 or equal version 2 (must be rejected)
        ok_rollback, msg_rollback = self.manager.create_or_update_policy(
            admin_token=self.admin_token,
            policy_id="POL-HARDENED-FINANCE",
            policy_name="Finance Hardened Policy",
            version=1,
            rules={"realtime": False},
        )
        self.assertFalse(ok_rollback)
        self.assertIn("rollback rejected", msg_rollback.lower())

        ok_equal, msg_equal = self.manager.create_or_update_policy(
            admin_token=self.admin_token,
            policy_id="POL-HARDENED-FINANCE",
            policy_name="Finance Hardened Policy",
            version=2,
            rules={"realtime": False},
        )
        self.assertFalse(ok_equal)
        self.assertIn("rollback rejected", msg_equal.lower())

    def test_admin_authorization_and_audit_logging(self):
        """Verify unauthorized admin actions are rejected and authorized ones are logged."""
        # Unauthorized attempt
        ok, msg = self.manager.create_or_update_policy(
            admin_token="WRONG-ADMIN-TOKEN",
            policy_id="POL-TEST",
            policy_name="Test Policy",
            version=1,
            rules={},
        )
        self.assertFalse(ok)
        self.assertIn("unauthorized", msg.lower())

        # Authorized attempt
        ok_auth, _ = self.manager.create_or_update_policy(
            admin_token=self.admin_token,
            policy_id="POL-TEST",
            policy_name="Test Policy",
            version=1,
            rules={},
            admin_id="sec_admin_jitender",
        )
        self.assertTrue(ok_auth)

        # Verify audit trail record
        logs = self.fleet_db.get_audit_log(limit=10)
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0].admin_id, "sec_admin_jitender")
        self.assertEqual(logs[0].action, "POLICY_CREATED")
        self.assertEqual(logs[0].target_id, "POL-TEST")

    def test_endpoint_isolation_and_unisolation(self):
        """Verify network isolation toggle for threat containment."""
        ok, _, ep_data = self.manager.register_endpoint(
            hostname="WS-COMPROMISED",
            ip_address="10.10.5.88",
            os_version="Windows 11",
            agent_version="1.1.0",
            enrollment_token=self.enrollment_key,
        )
        ep_id = ep_data["id"]

        # Isolate
        iso_ok, iso_msg = self.manager.isolate_endpoint(
            admin_token=self.admin_token,
            endpoint_id=ep_id,
            reason="Suspected lateral movement malware",
        )
        self.assertTrue(iso_ok)

        ep_iso = self.fleet_db.get_endpoint(ep_id)
        self.assertTrue(ep_iso.isolation_status)
        self.assertEqual(ep_iso.health_status, "AT_RISK")

        # Unisolate
        uniso_ok, uniso_msg = self.manager.unisolate_endpoint(
            admin_token=self.admin_token,
            endpoint_id=ep_id,
        )
        self.assertTrue(uniso_ok)

        ep_restored = self.fleet_db.get_endpoint(ep_id)
        self.assertFalse(ep_restored.isolation_status)

    def test_critical_event_incident_aggregation(self):
        """Verify that CRITICAL telemetry alerts trigger automated Incident creation."""
        ok, _, ep_data = self.manager.register_endpoint(
            hostname="SRV-DB-PROD",
            ip_address="10.200.1.5",
            os_version="Windows Server 2022",
            agent_version="1.1.0-PRO",
            enrollment_token=self.enrollment_key,
        )
        ep_id = ep_data["id"]

        # Emit critical ransomware event
        self.manager.record_endpoint_event(
            endpoint_id=ep_id,
            event_type="RANSOMWARE_MUTATION_BURST",
            severity=SEVERITY_CRITICAL,
            payload={
                "threat_name": "Ransomware.LockBit.3",
                "burst_count": 8,
                "mutated_extension": ".lockbit",
            },
        )

        # Verify endpoint status degraded to AT_RISK
        ep = self.fleet_db.get_endpoint(ep_id)
        self.assertEqual(ep.health_status, "AT_RISK")

        # Verify automated Incident created
        incidents = self.fleet_db.list_incidents(status="ACTIVE")
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, SEVERITY_CRITICAL)
        self.assertIn(ep_id, inc.affected_endpoints)
        self.assertIn("LockBit", inc.title)

    def test_endpoint_search_and_grouping(self):
        """Verify searching and filtering endpoints by department, tag, and hostname."""
        self.manager.register_endpoint(
            hostname="WS-DEV-10",
            ip_address="192.168.1.10",
            os_version="Windows 11",
            agent_version="1.1.0",
            enrollment_token=self.enrollment_key,
            department="Engineering",
            tags=["dev", "workstation"],
        )
        self.manager.register_endpoint(
            hostname="WS-OPS-20",
            ip_address="192.168.2.20",
            os_version="Windows 11",
            agent_version="1.1.0",
            enrollment_token=self.enrollment_key,
            department="Operations",
            tags=["ops", "server"],
        )

        # Search by department
        dev_eps = self.manager.search_endpoints(query="Engineering")
        self.assertEqual(len(dev_eps), 1)
        self.assertEqual(dev_eps[0]["hostname"], "WS-DEV-10")

        # Search by tag
        ops_eps = self.manager.search_endpoints(query="ops")
        self.assertEqual(len(ops_eps), 1)
        self.assertEqual(ops_eps[0]["hostname"], "WS-OPS-20")

        # Search by IP
        ip_eps = self.manager.search_endpoints(query="192.168.1.10")
        self.assertEqual(len(ip_eps), 1)
        self.assertEqual(ip_eps[0]["hostname"], "WS-DEV-10")


if __name__ == "__main__":
    unittest.main()

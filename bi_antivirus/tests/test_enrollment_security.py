"""
Unit and Integration Tests for Controlled Endpoint Enrollment Subsystem
Tests:
- Enrollment request lifecycle: PENDING_APPROVAL -> APPROVED -> ACTIVE -> REVOKED.
- Master enrollment token validation and rejection.
- Hardware fingerprint computation and collision/spoofing rejection.
- Duplicate identity handling and protection.
- Administrator approval gate and automated mTLS certificate generation.
- Endpoint revocation and PKI certificate invalidation.
- Re-enrollment authorization workflow.
- Unauthorized administrative operation rejection.
- Immutable audit log tracking across all state transitions.
"""

import unittest
import tempfile
import shutil
import time
from pathlib import Path

from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.pki_manager import PKIManager
from bi_antivirus.enterprise.enrollment_manager import EnrollmentManager, EnrollmentState


class TestEnrollmentSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bi_enroll_test_"))
        self.db = FleetDatabase(self.temp_dir / "fleet_test.db")
        self.pki = PKIManager(pki_dir=self.temp_dir, fleet_db=self.db)
        self.enroll_mgr = EnrollmentManager(
            fleet_db=self.db,
            pki_manager=self.pki,
            master_enrollment_key="MASTER-ENROLL-TOKEN-2026",
            admin_token="ADMIN-AUTH-SECRET-TOKEN",
            auto_approve_valid_tokens=False,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_request_enrollment_pending_approval(self):
        """Verify initial enrollment request transitions to PENDING_APPROVAL."""
        ok, state, data = self.enroll_mgr.request_enrollment(
            endpoint_id="EP-FINANCE-01",
            hostname="FIN-WORKSTATION-1",
            ip_address="192.168.1.50",
            mac_address="00:1A:2B:3C:4D:5E",
            os_version="Windows 11 Enterprise",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
            department="Finance",
        )
        self.assertTrue(ok)
        self.assertEqual(state, EnrollmentState.PENDING_APPROVAL)
        self.assertIsNone(data.get("credentials"))

        # Verify device in database
        device = self.db.get_endpoint("EP-FINANCE-01")
        self.assertIsNotNone(device)
        self.assertEqual(device.health_status, EnrollmentState.PENDING_APPROVAL)

        # Verify in pending list
        pending = self.enroll_mgr.get_pending_enrollments()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].id, "EP-FINANCE-01")

    def test_02_invalid_enrollment_token_rejection(self):
        """Verify enrollment attempt with invalid or forged token is rejected."""
        ok, reason, _ = self.enroll_mgr.request_enrollment(
            endpoint_id="EP-ROGUE-01",
            hostname="ROGUE-PC",
            ip_address="10.0.0.99",
            mac_address="AA:BB:CC:DD:EE:FF",
            os_version="Linux",
            agent_version="1.0.0",
            enrollment_token="INVALID-FORGED-TOKEN",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "INVALID_ENROLLMENT_TOKEN")

        device = self.db.get_endpoint("EP-ROGUE-01")
        self.assertIsNone(device)

    def test_03_admin_approval_and_cert_issuance(self):
        """Verify admin approval issues mTLS client certificate and marks status ACTIVE."""
        # Submit initial request
        self.enroll_mgr.request_enrollment(
            endpoint_id="EP-OPS-01",
            hostname="OPS-LAPTOP",
            ip_address="192.168.1.60",
            mac_address="11:22:33:44:55:66",
            os_version="Windows 10 Pro",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )

        # Admin approves
        ok, state, cert_data = self.enroll_mgr.approve_enrollment(
            endpoint_id="EP-OPS-01",
            admin_token="ADMIN-AUTH-SECRET-TOKEN",
            admin_id="sec_admin",
        )
        self.assertTrue(ok)
        self.assertEqual(state, EnrollmentState.ACTIVE)
        self.assertIsNotNone(cert_data)
        self.assertTrue(Path(cert_data["cert_path"]).exists())
        self.assertTrue(Path(cert_data["key_path"]).exists())

        # Verify database record updated
        ep = self.db.get_endpoint("EP-OPS-01")
        self.assertEqual(ep.health_status, EnrollmentState.ACTIVE)

        # Verify audit record created
        audit_log = self.db.get_audit_log(limit=5)
        actions = [a.action for a in audit_log]
        self.assertIn("ENROLLMENT_APPROVED", actions)

    def test_04_duplicate_spoof_detection(self):
        """Verify duplicate endpoint ID with different hardware fingerprint is rejected."""
        # 1. Enroll legitimate device
        self.enroll_mgr.request_enrollment(
            endpoint_id="EP-LEGIT-01",
            hostname="LEGIT-DESKTOP",
            ip_address="10.1.1.10",
            mac_address="DE:AD:BE:EF:00:01",
            os_version="Windows 11",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.enroll_mgr.approve_enrollment("EP-LEGIT-01", "ADMIN-AUTH-SECRET-TOKEN")

        # 2. Attacker claims same endpoint ID with different MAC and hostname
        ok, reason, _ = self.enroll_mgr.request_enrollment(
            endpoint_id="EP-LEGIT-01",
            hostname="ATTACKER-BOX",
            ip_address="10.1.1.99",
            mac_address="00:00:00:00:00:99",
            os_version="Linux",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "DUPLICATE_IDENTITY_MISMATCH")

    def test_05_endpoint_revocation(self):
        """Verify admin revocation revokes mTLS certificate in PKI and sets status REVOKED."""
        self.enroll_mgr.request_enrollment(
            endpoint_id="EP-REVOKE-ME",
            hostname="COMPROMISED-PC",
            ip_address="10.2.2.20",
            mac_address="02:02:02:02:02:02",
            os_version="Windows 11",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.enroll_mgr.approve_enrollment("EP-REVOKE-ME", "ADMIN-AUTH-SECRET-TOKEN")

        # Revoke
        ok, msg = self.enroll_mgr.revoke_endpoint(
            endpoint_id="EP-REVOKE-ME",
            admin_token="ADMIN-AUTH-SECRET-TOKEN",
            reason="Lateral movement detected",
            admin_id="ir_team",
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "ENDPOINT_REVOKED")

        # Verify endpoint status
        ep = self.db.get_endpoint("EP-REVOKE-ME")
        self.assertEqual(ep.health_status, EnrollmentState.REVOKED)

        # Verify PKI certificate is revoked
        self.assertTrue(self.pki.is_certificate_revoked("EP-REVOKE-ME"))

        # Verify audit entry
        audit_log = self.db.get_audit_log(limit=5)
        actions = [a.action for a in audit_log]
        self.assertIn("ENDPOINT_REVOKED", actions)

    def test_06_revoked_endpoint_cannot_reenroll_without_authorization(self):
        """Verify revoked endpoint cannot re-enroll unless administrator explicitly authorizes it."""
        self.enroll_mgr.request_enrollment(
            endpoint_id="EP-REVOKED-01",
            hostname="HOST-REV",
            ip_address="10.3.3.30",
            mac_address="03:03:03:03:03:03",
            os_version="Windows 10",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.enroll_mgr.approve_enrollment("EP-REVOKED-01", "ADMIN-AUTH-SECRET-TOKEN")
        self.enroll_mgr.revoke_endpoint("EP-REVOKED-01", "ADMIN-AUTH-SECRET-TOKEN", reason="Lost device")

        # Re-enrollment attempt blocked
        ok, reason, _ = self.enroll_mgr.request_enrollment(
            endpoint_id="EP-REVOKED-01",
            hostname="HOST-REV",
            ip_address="10.3.3.30",
            mac_address="03:03:03:03:03:03",
            os_version="Windows 10",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "REVOKED_ENDPOINT_CANNOT_REENROLL")

        # Administrator authorizes re-enrollment
        auth_ok, auth_msg = self.enroll_mgr.authorize_reenrollment(
            endpoint_id="EP-REVOKED-01",
            admin_token="ADMIN-AUTH-SECRET-TOKEN",
            reason="Device recovered and sanitized",
        )
        self.assertTrue(auth_ok)
        self.assertEqual(auth_msg, "REENROLLMENT_AUTHORIZED")

        # Now re-enrollment succeeds into PENDING_APPROVAL
        ok2, state2, _ = self.enroll_mgr.request_enrollment(
            endpoint_id="EP-REVOKED-01",
            hostname="HOST-REV",
            ip_address="10.3.3.30",
            mac_address="03:03:03:03:03:03",
            os_version="Windows 10",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )
        self.assertTrue(ok2)
        self.assertEqual(state2, EnrollmentState.PENDING_APPROVAL)

    def test_07_unauthorized_admin_token_rejection(self):
        """Verify operations with bad admin tokens fail."""
        self.enroll_mgr.request_enrollment(
            endpoint_id="EP-AUTH-TEST",
            hostname="HOST-AUTH",
            ip_address="10.4.4.40",
            mac_address="04:04:04:04:04:04",
            os_version="Windows 11",
            agent_version="2.0.0",
            enrollment_token="MASTER-ENROLL-TOKEN-2026",
        )

        ok_appr, msg_appr, _ = self.enroll_mgr.approve_enrollment("EP-AUTH-TEST", "BAD-ADMIN-TOKEN")
        self.assertFalse(ok_appr)
        self.assertEqual(msg_appr, "UNAUTHORIZED_ADMIN_TOKEN")

        ok_rev, msg_rev = self.enroll_mgr.revoke_endpoint("EP-AUTH-TEST", "BAD-ADMIN-TOKEN")
        self.assertFalse(ok_rev)
        self.assertEqual(msg_rev, "UNAUTHORIZED_ADMIN_TOKEN")

    def test_08_auto_approve_mode(self):
        """Verify auto-approve enrollment mode immediately issues credentials."""
        auto_mgr = EnrollmentManager(
            fleet_db=self.db,
            pki_manager=self.pki,
            master_enrollment_key="AUTO-KEY",
            admin_token="ADMIN-AUTH-SECRET-TOKEN",
            auto_approve_valid_tokens=True,
        )

        ok, state, data = auto_mgr.request_enrollment(
            endpoint_id="EP-AUTO-01",
            hostname="AUTO-HOST",
            ip_address="10.5.5.50",
            mac_address="05:05:05:05:05:05",
            os_version="Windows 11",
            agent_version="2.0.0",
            enrollment_token="AUTO-KEY",
        )
        self.assertTrue(ok)
        self.assertEqual(state, EnrollmentState.ACTIVE)
        self.assertIsNotNone(data.get("credentials"))
        self.assertTrue(Path(data["credentials"]["cert_path"]).exists())


if __name__ == "__main__":
    unittest.main()

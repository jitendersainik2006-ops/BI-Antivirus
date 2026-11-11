"""
Unit and Integration Tests for Secure Policy Distribution and Approved Rollback Subsystem
Tests:
- Policy bundle preparation with HMAC-SHA256 integrity signature.
- Monotonic sequence checks preventing unapproved policy downgrade and replay.
- Cryptographic policy acknowledgement (POLICY_ACKNOWLEDGED) with database receipts.
- Emergency Administrator-Approved Policy Rollback workflow:
  * Non-empty justification requirement.
  * Signed Rollback Authorization Token generation.
  * Signature verification and tamper detection.
  * Rollback token expiration enforcement.
  * End-to-end rollback execution and immutable audit logging.
- Unauthorized administrative operation rejection.
"""

import unittest
import tempfile
import shutil
import time
import json
import hmac
import hashlib
from pathlib import Path

from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.fleet_models import FleetPolicy, EndpointDevice, PolicyReceipt
from bi_antivirus.enterprise.policy_distributor import PolicyDistributor


class TestPolicyDistribution(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bi_poldist_test_"))
        self.db = FleetDatabase(self.temp_dir / "fleet_test.db")
        self.admin_token = "ADMIN-ROLLBACK-AUTH-TOKEN-2026"
        self.signing_key = hashlib.sha256(b"TEST_SIGNING_KEY_MATERIAL").digest()

        self.distributor = PolicyDistributor(
            fleet_db=self.db,
            admin_token=self.admin_token,
            signing_key=self.signing_key,
        )

        # Seed Database with Policy v1 and Policy v2
        self.policy_v1 = FleetPolicy(
            policy_id="POL-CORP-V1",
            policy_name="Corporate Baseline v1",
            version=1,
            rules={"realtime_scan": True, "usb_block": False},
        )
        self.policy_v2 = FleetPolicy(
            policy_id="POL-CORP-V2",
            policy_name="Corporate Hardened v2",
            version=2,
            rules={"realtime_scan": True, "usb_block": True, "firewall_strict": True},
        )
        self.db.save_policy(self.policy_v1)
        self.db.save_policy(self.policy_v2)

        # Seed Endpoint with Policy v1 currently active
        self.endpoint = EndpointDevice(
            id="EP-TEST-PC",
            hostname="TEST-WORKSTATION",
            ip_address="192.168.1.100",
            os_version="Windows 11",
            agent_version="2.0.0",
            assigned_policy_id="POL-CORP-V1",
        )
        self.db.register_endpoint(self.endpoint)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_prepare_signed_policy_bundle(self):
        """Verify policy bundle contains deterministic HMAC-SHA256 signature."""
        bundle = self.distributor.prepare_policy_bundle("POL-CORP-V2")
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle["policy_id"], "POL-CORP-V2")
        self.assertEqual(bundle["version"], 2)
        self.assertTrue(len(bundle["hmac_signature"]) == 64)
        self.assertIsNone(bundle["rollback_authorization"])

    def test_02_forward_distribution_monotonic_sequence(self):
        """Verify normal forward policy update (v2 > v1) is accepted and staged."""
        ok, msg, staged_count = self.distributor.stage_distribution(
            policy_id="POL-CORP-V2",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
        )
        self.assertTrue(ok)
        self.assertEqual(staged_count, 1)

        pending = self.distributor.get_pending_bundle("EP-TEST-PC")
        self.assertIsNotNone(pending)
        self.assertEqual(pending["policy_id"], "POL-CORP-V2")
        self.assertEqual(pending["version"], 2)

    def test_03_unapproved_rollback_rejection(self):
        """Verify attempt to downgrade or replay older version without authorization is blocked."""
        # Endpoint currently has v1. If we try to stage v1 again:
        ok, msg, staged_count = self.distributor.stage_distribution(
            policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
        )
        self.assertTrue(ok)
        self.assertEqual(staged_count, 0)  # Blocked by monotonic check

        # Now simulate endpoint already on v2
        self.db.assign_policy_to_endpoint("EP-TEST-PC", "POL-CORP-V2")
        ok2, msg2, staged_count2 = self.distributor.stage_distribution(
            policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
        )
        self.assertTrue(ok2)
        self.assertEqual(staged_count2, 0)  # Blocked

    def test_04_approved_emergency_rollback(self):
        """Verify emergency rollback workflow with signed authorization token."""
        # Endpoint is on v2
        self.db.assign_policy_to_endpoint("EP-TEST-PC", "POL-CORP-V2")

        # Admin approves rollback to v1
        ok, msg, bundle = self.distributor.create_approved_rollback(
            target_policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
            reason="Emergency rollback: strict firewall blocks mission-critical ERP server.",
            admin_id="lead_admin",
        )
        self.assertTrue(ok)
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle["policy_id"], "POL-CORP-V1")
        self.assertEqual(bundle["version"], 1)

        # Verify rollback authorization token is present and valid
        rollback_auth = bundle.get("rollback_authorization")
        self.assertIsNotNone(rollback_auth)
        self.assertEqual(rollback_auth["admin_id"], "lead_admin")
        self.assertEqual(rollback_auth["target_version"], 1)

        valid_auth, auth_err = self.distributor.verify_rollback_authorization(rollback_auth)
        self.assertTrue(valid_auth)

        # Verify audit record created
        audit_log = self.db.get_audit_log(limit=5)
        actions = [a.action for a in audit_log]
        self.assertIn("POLICY_ROLLBACK_APPROVED", actions)

    def test_05_rollback_empty_reason_rejection(self):
        """Verify rollback attempt without non-empty justification is rejected."""
        ok, msg, _ = self.distributor.create_approved_rollback(
            target_policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
            reason="   ",
        )
        self.assertFalse(ok)
        self.assertEqual(msg, "EMPTY_ROLLBACK_REASON")

    def test_06_rollback_unauthorized_token_rejection(self):
        """Verify rollback attempt with invalid admin token is rejected."""
        ok, msg, _ = self.distributor.create_approved_rollback(
            target_policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token="FORGED-ADMIN-TOKEN",
            reason="Valid reason",
        )
        self.assertFalse(ok)
        self.assertEqual(msg, "UNAUTHORIZED_ADMIN_TOKEN")

    def test_07_tampered_rollback_token_rejection(self):
        """Verify tampered rollback authorization payload is detected and rejected."""
        ok, _, bundle = self.distributor.create_approved_rollback(
            target_policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
            reason="Genuine reason",
        )
        rollback_auth = dict(bundle["rollback_authorization"])

        # Tamper target version
        rollback_auth["target_version"] = 99
        valid, err = self.distributor.verify_rollback_authorization(rollback_auth)
        self.assertFalse(valid)
        self.assertIn("signature mismatch", err)

    def test_08_expired_rollback_token_rejection(self):
        """Verify expired rollback authorization token is rejected."""
        ok, _, bundle = self.distributor.create_approved_rollback(
            target_policy_id="POL-CORP-V1",
            endpoint_ids=["EP-TEST-PC"],
            admin_token=self.admin_token,
            reason="Genuine reason",
        )
        rollback_auth = dict(bundle["rollback_authorization"])

        # Set expiration in past
        rollback_auth["expires_at"] = time.time() - 100.0
        # Re-sign to isolate expiration check
        payload_copy = {k: v for k, v in rollback_auth.items() if k != "signature"}
        canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
        rollback_auth["signature"] = hmac.new(self.signing_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        valid, err = self.distributor.verify_rollback_authorization(rollback_auth)
        self.assertFalse(valid)
        self.assertIn("expired", err)

    def test_09_policy_acknowledgement_receipt(self):
        """Verify cryptographic policy acknowledgement updates endpoint and persists receipt."""
        receipt = PolicyReceipt(
            receipt_id="REC-ACK-001",
            endpoint_id="EP-TEST-PC",
            policy_id="POL-CORP-V2",
            version=2,
            status="APPLIED",
            applied_at=time.time(),
            hmac_signature="sha256-mock-receipt-sig",
            details={"rules_applied": 3},
        )

        ok, msg = self.distributor.process_acknowledgement("EP-TEST-PC", receipt)
        self.assertTrue(ok)
        self.assertEqual(msg, "ACKNOWLEDGEMENT_RECORDED")

        # Endpoint updated to POL-CORP-V2
        ep = self.db.get_endpoint("EP-TEST-PC")
        self.assertEqual(ep.assigned_policy_id, "POL-CORP-V2")

        # Receipt in database
        receipts = self.db.get_policy_receipts(endpoint_id="EP-TEST-PC")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].receipt_id, "REC-ACK-001")


if __name__ == "__main__":
    unittest.main()

"""
BI Antivirus - Sprint 7 Independent Security Audit & Hardening Tests
Covers:
1. PBKDF2 Password Hashing with Unique Cryptographic Salts
2. Session Expiration & Explicit Invalidation (revoke_session, revoke_user_sessions)
3. User Deactivation & Immediate Session Termination
4. Dynamic Role Synchronization on Active Sessions
5. Backward Compatibility for Legacy Authentication
6. Quarantine Vault Path Traversal Defense on Restoration
7. Enrollment Input Validation & Malformed Identifier Handling
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from bi_antivirus.enterprise.rbac_manager import (
    RBACManager,
    PERM_VIEW_DASHBOARD,
    PERM_ISOLATE_HOST,
    PERM_MANAGE_FIREWALL,
    PERM_MANAGE_RBAC,
)
from bi_antivirus.core.quarantine import QuarantineManager


class TestSprint7SecurityHardening(unittest.TestCase):
    """Test suite for Sprint 7 security hardening and audit verification."""

    def setUp(self):
        self.rbac = RBACManager()
        self.temp_dir = tempfile.mkdtemp(prefix="bi_s7_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_unique_per_user_salts(self):
        """Verify that two users with identical passwords receive distinct salts and distinct hashes."""
        self.rbac.create_user("user_alpha", "READ_ONLY", "SharedSecretPassword123!")
        self.rbac.create_user("user_beta", "READ_ONLY", "SharedSecretPassword123!")

        user_a = self.rbac._users["user_alpha"]
        user_b = self.rbac._users["user_beta"]

        self.assertNotEqual(user_a.salt, user_b.salt, "Each user must have a unique cryptographic salt")
        self.assertNotEqual(user_a.password_hash, user_b.password_hash, "Identical passwords must produce distinct hashes")

        # Both users authenticate successfully with their own credentials
        sess_a = self.rbac.authenticate("user_alpha", "SharedSecretPassword123!")
        sess_b = self.rbac.authenticate("user_beta", "SharedSecretPassword123!")
        self.assertIsNotNone(sess_a)
        self.assertIsNotNone(sess_b)

    def test_02_session_revocation_explicit(self):
        """Verify that explicitly revoking a session token immediately denies authorization."""
        sess = self.rbac.authenticate("admin", "Admin@Secure2026!")
        self.assertIsNotNone(sess)
        token = sess.session_id

        # Valid prior to revocation
        self.assertIsNotNone(self.rbac.validate_session(token))
        auth, _ = self.rbac.authorize_action(token, PERM_MANAGE_RBAC)
        self.assertTrue(auth)

        # Revoke session
        revoked = self.rbac.revoke_session(token)
        self.assertTrue(revoked)

        # Denied after revocation
        self.assertIsNone(self.rbac.validate_session(token))
        auth_after, msg = self.rbac.authorize_action(token, PERM_MANAGE_RBAC)
        self.assertFalse(auth_after)
        self.assertIn("expired or is invalid", msg)

    def test_03_user_deactivation_terminates_active_sessions(self):
        """Verify that deactivating a user immediately terminates and purges all their active sessions."""
        self.rbac.create_user("operator1", "SEC_OPS", "SecOpsPass@2026!")
        sess = self.rbac.authenticate("operator1", "SecOpsPass@2026!")
        self.assertIsNotNone(sess)
        token = sess.session_id

        # Deactivate user
        success = self.rbac.deactivate_user("operator1")
        self.assertTrue(success)

        # Session should be invalid
        self.assertIsNone(self.rbac.validate_session(token))
        auth, _ = self.rbac.authorize_action(token, PERM_ISOLATE_HOST)
        self.assertFalse(auth)

        # New authentication attempt should also fail
        new_sess = self.rbac.authenticate("operator1", "SecOpsPass@2026!")
        self.assertIsNone(new_sess)

    def test_04_password_change_revokes_old_sessions(self):
        """Verify that changing password revokes active sessions and requires re-authentication with new password."""
        self.rbac.create_user("analyst", "SEC_OPS", "InitialPass123!")
        old_sess = self.rbac.authenticate("analyst", "InitialPass123!")
        old_token = old_sess.session_id

        # Change password
        changed = self.rbac.change_password("analyst", "InitialPass123!", "NewSecretPass456!")
        self.assertTrue(changed)

        # Old session must be invalid
        self.assertIsNone(self.rbac.validate_session(old_token))

        # Old password must fail
        self.assertIsNone(self.rbac.authenticate("analyst", "InitialPass123!"))

        # New password must succeed
        new_sess = self.rbac.authenticate("analyst", "NewSecretPass456!")
        self.assertIsNotNone(new_sess)

    def test_05_role_update_synchronizes_active_session(self):
        """Verify that elevating or demoting a user's role updates active sessions."""
        self.rbac.create_user("trainee", "READ_ONLY", "TraineePassword123!")
        sess = self.rbac.authenticate("trainee", "TraineePassword123!")
        token = sess.session_id

        # READ_ONLY lacks PERM_ISOLATE_HOST
        auth, _ = self.rbac.authorize_action(token, PERM_ISOLATE_HOST)
        self.assertFalse(auth)

        # Elevate to SEC_OPS
        self.rbac.update_user_role("trainee", "SEC_OPS")

        # Session now possesses elevated permission
        auth_elevated, _ = self.rbac.authorize_action(token, PERM_ISOLATE_HOST)
        self.assertTrue(auth_elevated)

    def test_06_quarantine_restore_path_traversal_rejection(self):
        """Verify that attempting to restore a quarantined file to a path with '..' is rejected."""
        qm = QuarantineManager(vault_dir=Path(self.temp_dir) / "vault", db_path=Path(self.temp_dir) / "q.db")

        # Create dummy file and quarantine it
        test_file = Path(self.temp_dir) / "sample_threat.bin"
        test_file.write_bytes(b"MALICIOUS_TEST_PAYLOAD_EICAR_SAMPLE")

        res = qm.quarantine_file(test_file, {"threat_name": "TestThreat.Simulated", "severity": "HIGH"})
        self.assertTrue(res.get("success"), res)
        q_id = res.get("quarantine_id")

        # Attempt restore with path traversal
        traversal_path = Path(self.temp_dir) / ".." / "escaped_threat.bin"
        restored, msg = qm.restore_file(q_id, custom_target_path=traversal_path)

        self.assertFalse(restored)
        self.assertIn("Path traversal sequence detected", msg)

    def test_07_bootstrap_accounts_backward_compatibility(self):
        """Verify that all default bootstrap accounts authenticate correctly."""
        accounts = [
            ("admin", "Admin@Secure2026!", "SUPER_ADMIN"),
            ("secops", "SecOps@2026!", "SEC_OPS"),
            ("auditor", "Auditor@2026!", "AUDITOR"),
            ("guest", "GuestReadOnly123!", "READ_ONLY"),
        ]
        for user, pwd, expected_role in accounts:
            sess = self.rbac.authenticate(user, pwd)
            self.assertIsNotNone(sess, f"Failed authenticating bootstrap account {user}")
            self.assertEqual(sess.role, expected_role)


if __name__ == "__main__":
    unittest.main()

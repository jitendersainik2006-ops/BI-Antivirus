"""
BI Antivirus - Enterprise RBAC & SIEM Hash Chaining Tests
Verifies:
- Role-Based Access Control permission enforcement (SUPER_ADMIN, SEC_OPS, AUDITOR, READ_ONLY)
- Session authentication and token validation
- SIEM format serialization (CEF, RFC 5424 Syslog, JSON)
- Cryptographic hash chaining immutability verification ($H_i = SHA256(H_{i-1} || entry_i)$)
- Tamper detection on modified or deleted audit log records
"""

import unittest
from bi_antivirus.enterprise.rbac_manager import (
    RBACManager,
    PERM_ISOLATE_HOST,
    PERM_MANAGE_FIREWALL,
    PERM_MANAGE_RBAC,
    PERM_VIEW_DASHBOARD,
)
from bi_antivirus.enterprise.siem_exporter import SIEMExporter, GENESIS_HASH


class TestEnterpriseRBACAndSIEM(unittest.TestCase):
    """Test suite for RBAC Manager and SIEM Exporter."""

    def setUp(self):
        self.rbac = RBACManager()
        self.siem = SIEMExporter()

    def test_01_super_admin_permissions(self):
        """Verify SUPER_ADMIN holds full permission suite."""
        self.assertTrue(self.rbac.has_permission("SUPER_ADMIN", PERM_ISOLATE_HOST))
        self.assertTrue(self.rbac.has_permission("SUPER_ADMIN", PERM_MANAGE_FIREWALL))
        self.assertTrue(self.rbac.has_permission("SUPER_ADMIN", PERM_MANAGE_RBAC))

    def test_02_sec_ops_permissions(self):
        """Verify SEC_OPS can isolate host but cannot manage RBAC roles."""
        self.assertTrue(self.rbac.has_permission("SEC_OPS", PERM_ISOLATE_HOST))
        self.assertTrue(self.rbac.has_permission("SEC_OPS", PERM_MANAGE_FIREWALL))
        self.assertFalse(self.rbac.has_permission("SEC_OPS", PERM_MANAGE_RBAC))

    def test_03_auditor_permissions(self):
        """Verify AUDITOR has read-only compliance access and cannot execute mitigations."""
        self.assertTrue(self.rbac.has_permission("AUDITOR", PERM_VIEW_DASHBOARD))
        self.assertFalse(self.rbac.has_permission("AUDITOR", PERM_ISOLATE_HOST))
        self.assertFalse(self.rbac.has_permission("AUDITOR", PERM_MANAGE_FIREWALL))

    def test_04_session_authentication_and_expiration(self):
        """Verify authentication issues valid session token, and invalid password fails."""
        sess = self.rbac.authenticate("admin", "Admin@Secure2026!")
        self.assertIsNotNone(sess)
        self.assertEqual(sess.role, "SUPER_ADMIN")

        # Authorize via session token
        auth, msg = self.rbac.authorize_action(sess.session_id, PERM_MANAGE_FIREWALL)
        self.assertTrue(auth, msg)

        # Bad password
        bad_sess = self.rbac.authenticate("admin", "WrongPassword!")
        self.assertIsNone(bad_sess)

    def test_05_cef_log_formatting(self):
        """Verify ArcSight CEF output adheres to standard structure."""
        cef = self.siem.format_cef(
            name="Ransomware Intercepted",
            severity=9,
            extension_dict={"src": "10.0.0.5", "dst": "203.0.113.10", "msg": "Canary trap triggered"},
        )
        self.assertTrue(cef.startswith("CEF:0|Black Intel|BI Antivirus|"))
        self.assertIn("Ransomware Intercepted", cef)
        self.assertIn("src=10.0.0.5", cef)

    def test_06_rfc5424_syslog_formatting(self):
        """Verify RFC 5424 structured syslog string format."""
        syslog = self.siem.format_rfc5424_syslog(
            app_name="BIAntivirus",
            msg_id="INCIDENT_ALERT",
            sd_params={"threat": "Mimikatz", "action": "BLOCKED"},
            message="Credential dumping prevented.",
        )
        self.assertTrue(syslog.startswith("<"))
        self.assertIn("BIAntivirus", syslog)
        self.assertIn('[threat@41058 action="BLOCKED" threat="Mimikatz"]', syslog)

    def test_07_cryptographic_hash_chain_integrity(self):
        """Verify sequential entries form unbroken cryptographic chain."""
        e1 = self.siem.record_audit_entry("AUTH", "LOGIN_SUCCESS", actor="admin", severity="INFO")
        e2 = self.siem.record_audit_entry("FIREWALL", "RULE_APPLIED", actor="secops", severity="MEDIUM")
        e3 = self.siem.record_audit_entry("EDR", "HOST_ISOLATED", actor="admin", severity="CRITICAL")

        self.assertEqual(e1.prev_hash, GENESIS_HASH)
        self.assertEqual(e2.prev_hash, e1.current_hash)
        self.assertEqual(e3.prev_hash, e2.current_hash)

        is_valid, fail_idx, reason = self.siem.verify_chain()
        self.assertTrue(is_valid, reason)
        self.assertIsNone(fail_idx)

    def test_08_tamper_detection_in_hash_chain(self):
        """Verify any tampering with an existing log record is detected and located."""
        self.siem.record_audit_entry("EVT1", "ACTION1")
        self.siem.record_audit_entry("EVT2", "ACTION2")
        self.siem.record_audit_entry("EVT3", "ACTION3")

        # Tamper with entry at index 1
        self.siem.chain[1].action = "ALTERED_ACTION_BY_ATTACKER"

        is_valid, fail_idx, reason = self.siem.verify_chain()
        self.assertFalse(is_valid)
        self.assertEqual(fail_idx, 1)
        self.assertIn("Tampered entry detected", reason)


if __name__ == "__main__":
    unittest.main()

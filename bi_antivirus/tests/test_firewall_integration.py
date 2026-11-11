"""
BI Antivirus - Firewall Integration & Management Tests
Verifies:
- Active Windows Firewall profile status queries
- Staged firewall rule creation and review
- Mandatory administrator authorization gate enforcement
- Staged rule application and reversible rollback
"""

import unittest
from bi_antivirus.monitors.firewall_monitor import FirewallMonitor


class TestFirewallIntegration(unittest.TestCase):
    """Test suite for Firewall Monitor and staged rule lifecycle."""

    def setUp(self):
        # Clear staged rules dictionary
        FirewallMonitor._staged_rules.clear()
        FirewallMonitor._applied_rules.clear()
        self.valid_token = "BI-SEC-ADMIN-ROOT-2026"
        self.invalid_token = "BAD-TOKEN-123"

    def test_01_firewall_profile_status(self):
        """Verify Windows firewall profile retrieval returns structured status."""
        status = FirewallMonitor.get_firewall_profiles_status()
        self.assertIn("Domain", status)
        self.assertIn("Private", status)
        self.assertIn("Public", status)
        self.assertIn("all_active", status)

    def test_02_stage_firewall_rule(self):
        """Verify staging a firewall rule stores rule entry without executing state changes."""
        res = FirewallMonitor.stage_firewall_rule(
            rule_name="Block-Malicious-C2",
            direction="out",
            action="block",
            protocol="TCP",
            remote_port=4444,
            remote_ip="203.0.113.55",
        )
        self.assertTrue(res["success"])
        rule_id = res["rule_id"]
        self.assertIn("STAGE-", rule_id)

        staged_list = FirewallMonitor.list_staged_rules()
        self.assertEqual(len(staged_list), 1)
        self.assertEqual(staged_list[0]["rule_name"], "BI-FW-Block-Malicious-C2")
        self.assertEqual(staged_list[0]["status"], "STAGED")

    def test_03_apply_rule_unauthorized_token_rejected(self):
        """Verify applying a staged rule with an invalid administrator token is rejected."""
        stage_res = FirewallMonitor.stage_firewall_rule(rule_name="Test-Rule")
        rule_id = stage_res["rule_id"]

        apply_res = FirewallMonitor.apply_staged_rule(rule_id, admin_token=self.invalid_token)
        self.assertFalse(apply_res["success"])
        self.assertIn("UNAUTHORIZED", apply_res["error"])

    def test_04_apply_and_rollback_rule(self):
        """Verify valid admin token applies staged rule, and rollback successfully removes it."""
        stage_res = FirewallMonitor.stage_firewall_rule(
            rule_name="Temp-Containment",
            direction="out",
            action="block",
            protocol="TCP",
            remote_port=8088,
        )
        rule_id = stage_res["rule_id"]

        apply_res = FirewallMonitor.apply_staged_rule(rule_id, admin_token=self.valid_token)
        # Note: In non-elevated environment, apply_res will report success or requires elevation safely
        if apply_res["success"]:
            self.assertEqual(apply_res["status"], "APPLIED")
            self.assertIn("BI-FW-Temp-Containment", FirewallMonitor._applied_rules)

            # Rollback
            rb_res = FirewallMonitor.rollback_firewall_rule("Temp-Containment", admin_token=self.valid_token)
            self.assertTrue(rb_res["success"])
            self.assertEqual(rb_res["status"], "ROLLED_BACK")
            self.assertNotIn("BI-FW-Temp-Containment", FirewallMonitor._applied_rules)
        else:
            self.assertIn("elevation", apply_res["error"].lower())

    def test_05_rollback_unauthorized_token_rejected(self):
        """Verify rollback with an invalid admin token is rejected."""
        rb_res = FirewallMonitor.rollback_firewall_rule("Some-Rule", admin_token=self.invalid_token)
        self.assertFalse(rb_res["success"])
        self.assertIn("UNAUTHORIZED", rb_res["error"])


if __name__ == "__main__":
    unittest.main()

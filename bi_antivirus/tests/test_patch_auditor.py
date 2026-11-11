"""
BI Antivirus - Test Suite for Software Inventory & Patch Auditor
Verifies:
- Semantic version parsing and tuple comparisons
- CVE advisory matching across installed software versions
- Detection of confirmed vulnerable vs up-to-date software
- Database persistence of software inventory and CVE advisories
- Zero silent installations policy (manual remediation guidance present)
"""

import unittest
from pathlib import Path

from bi_antivirus.monitors.patch_auditor import (
    SoftwarePatchAuditor,
    parse_version_tuple,
    is_version_vulnerable,
    DEFAULT_CVE_ADVISORIES,
)
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.config import SCRATCH_DIR


class TestPatchAuditor(unittest.TestCase):
    """Test suite for Software Inventory & Patch Auditor."""

    def setUp(self):
        self.scratch_dir = SCRATCH_DIR / "test_patch_scratch"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.scratch_dir / "test_patch_history.db"
        self.history_db = HistoryDatabase(db_path=self.db_path)
        self.auditor = SoftwarePatchAuditor(history_db=self.history_db)

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

    def test_semantic_version_parsing(self):
        """Verify version string normalization to numeric integer tuples."""
        self.assertEqual(parse_version_tuple("23.01"), (23, 1, 0, 0))
        self.assertEqual(parse_version_tuple("7.3.2.1"), (7, 3, 2, 1))
        self.assertEqual(parse_version_tuple("v2.45.0.windows.1"), (2, 45, 0, 1))
        self.assertEqual(parse_version_tuple("125.0.6422.141"), (125, 0, 6422, 141))
        self.assertEqual(parse_version_tuple(""), (0, 0, 0, 0))
        self.assertEqual(parse_version_tuple("invalid"), (0, 0, 0, 0))

    def test_version_vulnerability_boundary_checks(self):
        """Verify boundary comparisons for affected and fixed versions."""
        # 7-Zip fixed in 23.01
        is_vuln, is_up = is_version_vulnerable("23.00", "0.0.0", "23.01")
        self.assertTrue(is_vuln)
        self.assertFalse(is_up)

        is_vuln, is_up = is_version_vulnerable("22.01", "0.0.0", "23.01")
        self.assertTrue(is_vuln)

        is_vuln, is_up = is_version_vulnerable("23.01", "0.0.0", "23.01")
        self.assertFalse(is_vuln)
        self.assertTrue(is_up)

        is_vuln, is_up = is_version_vulnerable("24.08", "0.0.0", "23.01")
        self.assertFalse(is_vuln)
        self.assertTrue(is_up)

        # WinRAR fixed in 6.23
        is_vuln, is_up = is_version_vulnerable("6.22", "0.0.0", "6.23")
        self.assertTrue(is_vuln)

        is_vuln, is_up = is_version_vulnerable("6.23", "0.0.0", "6.23")
        self.assertFalse(is_vuln)
        self.assertTrue(is_up)

        # Min version boundary checks
        is_vuln, is_up = is_version_vulnerable("1.0.0", "2.0.0", "3.0.0")
        self.assertFalse(is_vuln)

        is_vuln, is_up = is_version_vulnerable("2.5.0", "2.0.0", "3.0.0")
        self.assertTrue(is_vuln)

        is_vuln, is_up = is_version_vulnerable("3.0.0", "2.0.0", "3.0.0")
        self.assertFalse(is_vuln)
        self.assertTrue(is_up)

    def test_single_application_audit(self):
        """Verify vulnerability determination and remediation guidance generation."""
        # 1. Vulnerable 7-Zip
        vulnerable_app = {
            "app_name": "7-Zip 23.00 (x64 edition)",
            "version": "23.00",
            "publisher": "Igor Pavlov",
            "install_location": r"C:\Program Files\7-Zip",
        }
        res_vuln = self.auditor.audit_application(vulnerable_app)
        self.assertEqual(res_vuln["status"], "CONFIRMED_VULNERABLE")
        self.assertTrue(res_vuln["matched_cve"].startswith("CVE-2023-"))
        self.assertIn("remediation_playbook", res_vuln)
        self.assertTrue(res_vuln["requires_admin_action"])

        # 2. Up-to-date 7-Zip
        updated_app = {
            "app_name": "7-Zip 24.08 (x64 edition)",
            "version": "24.08",
            "publisher": "Igor Pavlov",
            "install_location": r"C:\Program Files\7-Zip",
        }
        res_ok = self.auditor.audit_application(updated_app)
        self.assertEqual(res_ok["status"], "UP_TO_DATE")
        self.assertFalse(res_ok["requires_admin_action"])

        # 3. Unknown unmanaged software
        unknown_app = {
            "app_name": "Internal Custom Company Tool v1.0",
            "version": "1.0",
            "publisher": "Acme Corp",
            "install_location": r"C:\Tools\Acme",
        }
        res_unk = self.auditor.audit_application(unknown_app)
        self.assertEqual(res_unk["status"], "UNKNOWN")

    def test_database_advisory_and_inventory_persistence(self):
        """Verify advisories and audited software records persist in history database."""
        # Record custom advisory
        self.history_db.record_cve_advisory(
            cve_id="CVE-2026-99999",
            product_name="SuperTool",
            vendor="SuperOrg",
            affected_versions_min="0.0.0",
            affected_versions_max="4.9.9",
            fixed_version="5.0",
            severity="CRITICAL",
            title="Remote code execution in SuperTool parser.",
            description="Buffer overflow in parser.",
        )

        advisories = self.history_db.get_cve_advisories()
        self.assertTrue(any(a["cve_id"] == "CVE-2026-99999" for a in advisories))

        # Record inventory
        self.history_db.record_software_inventory([
            {
                "app_name": "SuperTool",
                "version": "4.2",
                "publisher": "SuperOrg",
                "status": "CONFIRMED_VULNERABLE",
                "matched_cve": "CVE-2026-99999",
            }
        ])

        inv = self.history_db.get_software_inventory()
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["app_name"], "SuperTool")
        self.assertEqual(inv[0]["status"], "CONFIRMED_VULNERABLE")


if __name__ == "__main__":
    unittest.main()

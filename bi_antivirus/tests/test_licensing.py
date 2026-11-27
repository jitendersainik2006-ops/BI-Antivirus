"""
Unit Tests for BI Antivirus Licensing & Feature Entitlement System
Tests Free vs Premium tiers, daily scan quotas, algorithmic key validation,
tamper-evident storage, and scan policy enforcement.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.config import (
    EDITION_FREE,
    EDITION_PREMIUM,
    SCAN_TYPE_QUICK,
    SCAN_TYPE_FULL,
    SCAN_TYPE_DEEP,
    SCAN_TYPE_CUSTOM,
)
from bi_antivirus.core.licensing import (
    LicenseManager,
    generate_license_key,
    validate_license_key,
)


class TestLicensingSystem(unittest.TestCase):
    """Test suite for Free/Premium entitlement architecture."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.entitlement_file = Path(self.temp_dir.name) / "test_entitlement.json"
        self.mgr = LicenseManager(entitlement_path=self.entitlement_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_default_edition_is_free(self):
        """Verify new installation defaults to Free edition."""
        self.assertEqual(self.mgr.get_edition(), EDITION_FREE)
        self.assertFalse(self.mgr.is_premium())
        self.assertEqual(self.mgr.get_remaining_scans(), 5)

    def test_02_license_key_generation_and_validation(self):
        """Verify algorithmic key generation and verification passes."""
        key = generate_license_key("PREMIUM")
        self.assertTrue(key.startswith("BI-PREM-7170-"))

        is_valid, tier, msg = validate_license_key(key)
        self.assertTrue(is_valid)
        self.assertEqual(tier, EDITION_PREMIUM)

    def test_03_invalid_license_key_rejected(self):
        """Verify altered or malformed keys fail validation."""
        # Invalid block
        is_valid, _, msg = validate_license_key("INVALID-KEY-1234")
        self.assertFalse(is_valid)

        # Altered checksum
        valid_key = generate_license_key("PREMIUM")
        parts = valid_key.split("-")
        tampered_chk = "ZZZZ" if parts[-1] != "ZZZZ" else "AAAA"
        bad_key = "-".join(parts[:-1] + [tampered_chk])

        is_valid, _, msg = validate_license_key(bad_key)
        self.assertFalse(is_valid)
        self.assertIn("checksum", msg.lower())

    def test_04_activate_and_deactivate_premium(self):
        """Verify successful activation unlocks Premium and deactivation reverts to Free."""
        key = generate_license_key("PREMIUM")
        ok, msg = self.mgr.activate(key)
        self.assertTrue(ok)
        self.assertEqual(self.mgr.get_edition(), EDITION_PREMIUM)
        self.assertTrue(self.mgr.is_premium())
        self.assertEqual(self.mgr.get_remaining_scans(), -1)  # Unlimited

        # Deep Scan is allowed in Premium
        allowed, _ = self.mgr.can_perform_scan(SCAN_TYPE_DEEP)
        self.assertTrue(allowed)

        # Deactivate
        ok, _ = self.mgr.deactivate()
        self.assertTrue(ok)
        self.assertEqual(self.mgr.get_edition(), EDITION_FREE)
        self.assertFalse(self.mgr.is_premium())

    def test_05_deep_scan_locked_on_free_edition(self):
        """Verify Deep Scan is strictly blocked on Free edition."""
        self.assertEqual(self.mgr.get_edition(), EDITION_FREE)
        allowed, reason = self.mgr.can_perform_scan(SCAN_TYPE_DEEP)
        self.assertFalse(allowed)
        self.assertIn("Premium", reason)

    def test_06_free_scan_allowance_quota_enforcement(self):
        """Verify daily scan quota counts down and blocks scans when exhausted."""
        self.assertEqual(self.mgr.get_remaining_scans(), 5)

        for i in range(5):
            allowed, _ = self.mgr.can_perform_scan(SCAN_TYPE_QUICK)
            self.assertTrue(allowed)
            self.mgr.record_scan_performed(SCAN_TYPE_QUICK)
            self.assertEqual(self.mgr.get_remaining_scans(), 5 - (i + 1))

        # 6th scan must be rejected
        allowed, reason = self.mgr.can_perform_scan(SCAN_TYPE_QUICK)
        self.assertFalse(allowed)
        self.assertIn("daily scan allowance reached", reason.lower())

    def test_07_tamper_evident_entitlement_protection(self):
        """Verify modifying local entitlement file invalidates state and falls back to Free."""
        key = generate_license_key("PREMIUM")
        self.mgr.activate(key)
        self.assertTrue(self.mgr.is_premium())

        # Tamper with the raw file directly on disk
        with open(self.entitlement_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        raw_data["scans_used_today"] = 0
        raw_data["max_free_scans_per_day"] = 999
        # Do not update _hmac -> signature mismatch
        with open(self.entitlement_file, "w", encoding="utf-8") as f:
            json.dump(raw_data, f)

        # Reload with fresh manager instance
        fresh_mgr = LicenseManager(entitlement_path=self.entitlement_file)
        self.assertEqual(fresh_mgr.get_edition(), EDITION_FREE)
        self.assertFalse(fresh_mgr.is_premium())
        self.assertTrue(fresh_mgr._state.get("tamper_detected"))


if __name__ == "__main__":
    unittest.main()

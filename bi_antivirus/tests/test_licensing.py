"""
Unit Tests for BI Antivirus Licensing & Feature Entitlement System
=================================================================
Tests Free vs Premium tiers, daily scan quotas, asymmetric RSA-2048
license verification, tamper-evident storage, expired/forged token rejection,
and scan policy enforcement.
"""

import os
import sys
import json
import time
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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
    validate_license_token,
    verify_rsa_signature,
)

# Import issuer for test generation
try:
    from scripts.issuer.issue_license import issue_license, sign_payload
except ImportError:
    issue_license = None


class TestLicensingSystem(unittest.TestCase):
    """Test suite for Free/Premium entitlement architecture and asymmetric security."""

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

    def test_02_legacy_license_key_validation(self):
        """Verify legacy developer key format validation passes."""
        key = generate_license_key("PREMIUM")
        self.assertTrue(key.startswith("BI-PREM-7170-"))

        is_valid, tier, msg = validate_license_key(key)
        self.assertTrue(is_valid)
        self.assertEqual(tier, EDITION_PREMIUM)

    def test_03_invalid_license_key_rejected(self):
        """Verify malformed keys fail validation."""
        is_valid, _, msg = validate_license_key("INVALID-KEY-1234")
        self.assertFalse(is_valid)

        is_valid, _, msg = validate_license_key("")
        self.assertFalse(is_valid)

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
        """Verify modifying local entitlement file with forged Premium tier reverts to Free."""
        # Forge an entitlement file claiming Premium without a valid token
        with open(self.entitlement_file, "w", encoding="utf-8") as f:
            json.dump({
                "edition": EDITION_PREMIUM,
                "license_key": "FORGED-KEY-NOT-VALID",
                "scans_used_today": 0,
                "max_free_scans_per_day": 999,
            }, f)

        # Reload with fresh manager instance
        fresh_mgr = LicenseManager(entitlement_path=self.entitlement_file)
        self.assertEqual(fresh_mgr.get_edition(), EDITION_FREE)
        self.assertFalse(fresh_mgr.is_premium())
        self.assertTrue(fresh_mgr._state.get("tamper_detected"))

    def test_08_asymmetric_rsa_token_validation(self):
        """Verify valid asymmetric RSA-2048 license token activates Premium."""
        if issue_license is None:
            self.skipTest("Issuer CLI module not available in this environment")

        token = issue_license(tier="PREMIUM", validity_days=365, issued_to="QA Lab")
        self.assertTrue(token.startswith("BI-LIC-V2."))

        ok, tier, payload, msg = validate_license_token(token)
        self.assertTrue(ok)
        self.assertEqual(tier, EDITION_PREMIUM)
        self.assertIn("QA Lab", msg)

        # Activate on manager
        ok, act_msg = self.mgr.activate(token)
        self.assertTrue(ok)
        self.assertEqual(self.mgr.get_edition(), EDITION_PREMIUM)
        self.assertTrue(self.mgr.is_premium())
        self.assertEqual(self.mgr.get_remaining_scans(), -1)

    def test_09_modified_asymmetric_token_rejected(self):
        """Verify tampering with token payload or signature is rejected cryptographically."""
        if issue_license is None:
            self.skipTest("Issuer CLI module not available in this environment")

        token = issue_license(tier="PREMIUM", validity_days=365)
        parts = token.split(".")

        # Tamper with the payload block
        tampered_payload = parts[1][:-2] + ("AA" if not parts[1].endswith("AA") else "BB")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        ok, _, _, msg = validate_license_token(tampered_token)
        self.assertFalse(ok)
        self.assertIn("validation failed", msg.lower())

        # Tamper with the signature block
        tampered_sig = parts[2][:-2] + ("XX" if not parts[2].endswith("XX") else "YY")
        tampered_token2 = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        ok2, _, _, msg2 = validate_license_token(tampered_token2)
        self.assertFalse(ok2)
        self.assertIn("validation failed", msg2.lower())

    def test_10_expired_asymmetric_token_rejected(self):
        """Verify expired license token is rejected with proper expiration notice."""
        if issue_license is None:
            self.skipTest("Issuer CLI module not available in this environment")

        # Create expired payload (expired 10 days ago)
        now = int(time.time())
        expired_payload = {
            "product": "BI-ANTIVIRUS",
            "tier": "PREMIUM",
            "license_id": "BI-PREM-7170-EXPIRED-01",
            "issued_to": "Expired Test User",
            "issued_at": now - (30 * 86400),
            "expires_at": now - (10 * 86400),
            "features": ["deep_scan"],
        }
        canonical_json = json.dumps(expired_payload, sort_keys=True, separators=(",", ":"))
        expired_token = sign_payload(canonical_json)

        ok, tier, _, msg = validate_license_token(expired_token)
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

    def test_11_incorrect_tier_token_rejected(self):
        """Verify tokens with non-Premium tiers do not grant Premium."""
        if issue_license is None:
            self.skipTest("Issuer CLI module not available in this environment")

        now = int(time.time())
        free_payload = {
            "product": "BI-ANTIVIRUS",
            "tier": "STANDARD",
            "license_id": "BI-STD-7170-TEST-01",
            "issued_to": "Standard User",
            "issued_at": now,
            "expires_at": now + (365 * 86400),
            "features": [],
        }
        canonical_json = json.dumps(free_payload, sort_keys=True, separators=(",", ":"))
        free_token = sign_payload(canonical_json)

        ok, tier, _, msg = validate_license_token(free_token)
        self.assertFalse(ok)
        self.assertIn("does not grant premium", msg.lower())

    def test_12_offline_verification_and_restart_persistence(self):
        """Verify offline verification works without network and persists across restarts."""
        if issue_license is None:
            self.skipTest("Issuer CLI module not available in this environment")

        token = issue_license(tier="PREMIUM", validity_days=180, issued_to="Offline Endpoint")
        ok, _ = self.mgr.activate(token)
        self.assertTrue(ok)

        # Simulate application restart: load from disk with fresh manager instance
        restarted_mgr = LicenseManager(entitlement_path=self.entitlement_file)
        self.assertEqual(restarted_mgr.get_edition(), EDITION_PREMIUM)
        self.assertTrue(restarted_mgr.is_premium())
        self.assertEqual(restarted_mgr.get_remaining_scans(), -1)
        self.assertFalse(restarted_mgr._state.get("tamper_detected"))


if __name__ == "__main__":
    unittest.main()

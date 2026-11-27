"""
BI Antivirus - Central Licensing & Feature Entitlement System
Enforces Free vs Premium edition policies, configurable daily scan allowances,
tamper-evident local entitlement storage, and algorithmic key validation.
"""

import os
import json
import time
import hmac
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from bi_antivirus.config import (
    DATA_DIR,
    EDITION_FREE,
    EDITION_PREMIUM,
    SCAN_TYPE_QUICK,
    SCAN_TYPE_FULL,
    SCAN_TYPE_CUSTOM,
    SCAN_TYPE_DEEP,
    DEFAULT_MAX_FREE_SCANS_PER_DAY,
    LICENSE_ENTITLEMENT_PATH,
    load_settings,
)

# Secret salt for algorithmic license key validation & entitlement HMAC sealing
_KEY_SALT = b"BLACK_INTEL_717_LICENSE_VERIFICATION_SECRET_SALT_2026"
_ENTITLEMENT_SALT = b"BLACK_INTEL_ENTITLEMENT_INTEGRITY_SALT_2026"


def _compute_key_checksum(payload: str) -> str:
    """Derive a 4-character deterministic checksum from license payload."""
    h = hmac.new(_KEY_SALT, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return h[:4].upper()


def generate_license_key(tier: str = "PREMIUM", seed: Optional[str] = None) -> str:
    """
    Generate a cryptographically valid Black Intel license key.
    Format: BI-PREM-7170-XXXX-XXXX-YYYY (where YYYY is checksum of first 3 blocks)
    """
    prefix = "BI-PREM" if tier.upper() == "PREMIUM" else "BI-ENTP"
    block1 = "7170"
    if seed:
        s_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest().upper()
        block2 = s_hash[:4]
        block3 = s_hash[4:8]
    else:
        rnd = os.urandom(8).hex().upper()
        block2 = rnd[:4]
        block3 = rnd[4:8]

    base_payload = f"{prefix}-{block1}-{block2}-{block3}"
    checksum = _compute_key_checksum(base_payload)
    return f"{base_payload}-{checksum}"


def validate_license_key(key: str) -> Tuple[bool, str, str]:
    """
    Algorithmic verification of license key.
    Returns: (is_valid, tier, error_or_success_message)
    """
    if not key or not isinstance(key, str):
        return False, "", "Empty or invalid license key string."

    clean_key = key.strip().upper()
    if clean_key.startswith("BI-PREM-"):
        tier = EDITION_PREMIUM
        body_parts = clean_key[len("BI-PREM-"):].split("-")
    elif clean_key.startswith("BI-ENTP-"):
        tier = "ENTERPRISE"
        body_parts = clean_key[len("BI-ENTP-"):].split("-")
    else:
        return False, "", "Invalid key format. Expected format: BI-PREM-XXXX-XXXX-XXXX-XXXX"

    if len(body_parts) != 4:
        return False, "", "Invalid key format. Expected format: BI-PREM-XXXX-XXXX-XXXX-XXXX"

    for b in body_parts:
        if len(b) != 4 or not b.isalnum():
            return False, "", "Each license key block must contain exactly 4 alphanumeric characters."

    block1, block2, block3, chk = body_parts
    base_payload = f"BI-{'PREM' if tier == EDITION_PREMIUM else 'ENTP'}-{block1}-{block2}-{block3}"
    expected_checksum = _compute_key_checksum(base_payload)

    if chk != expected_checksum:
        return False, "", "Cryptographic license checksum validation failed. Key is invalid or mistyped."

    return True, tier, f"Valid {tier} license."


class LicenseManager:
    """
    Manages edition state, daily scan usage counters, and tamper-evident local cache.
    """

    def __init__(self, entitlement_path: Optional[Path] = None):
        self.entitlement_path = entitlement_path or LICENSE_ENTITLEMENT_PATH
        self._state: Dict[str, Any] = {
            "edition": EDITION_FREE,
            "license_key": None,
            "activated_at": None,
            "expires_at": None,
            "scans_used_today": 0,
            "last_reset_date": datetime.date.today().isoformat(),
            "max_free_scans_per_day": DEFAULT_MAX_FREE_SCANS_PER_DAY,
            "tamper_detected": False,
        }
        self.load_entitlement()

    def load_entitlement(self) -> None:
        """Load and cryptographically verify the local entitlement file."""
        settings = load_settings()
        self._state["max_free_scans_per_day"] = settings.get("max_free_scans_per_day", DEFAULT_MAX_FREE_SCANS_PER_DAY)

        if not self.entitlement_path.exists():
            self._check_daily_reset()
            self.save_entitlement()
            return

        try:
            with open(self.entitlement_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            stored_hmac = data.get("_hmac", "")
            payload_copy = {k: v for k, v in data.items() if k != "_hmac"}
            computed_hmac = self._sign_payload(payload_copy)

            if not hmac.compare_digest(stored_hmac, computed_hmac):
                # Tamper detected - fall back to Free safely
                self._state["edition"] = EDITION_FREE
                self._state["license_key"] = None
                self._state["tamper_detected"] = True
                self._check_daily_reset()
                self.save_entitlement()
                return

            self._state.update(payload_copy)
            self._state["tamper_detected"] = False

            # Verify active key still passes validation if premium
            if self._state.get("edition") == EDITION_PREMIUM:
                active_key = self._state.get("license_key", "")
                is_valid, _, _ = validate_license_key(active_key)
                if not is_valid:
                    self._state["edition"] = EDITION_FREE
                    self._state["license_key"] = None

            self._check_daily_reset()
        except Exception:
            self._state["edition"] = EDITION_FREE
            self._check_daily_reset()
            self.save_entitlement()

    def save_entitlement(self) -> bool:
        """Sign and persist current entitlement state to disk."""
        try:
            payload = {
                "edition": self._state["edition"],
                "license_key": self._state["license_key"],
                "activated_at": self._state["activated_at"],
                "expires_at": self._state["expires_at"],
                "scans_used_today": self._state["scans_used_today"],
                "last_reset_date": self._state["last_reset_date"],
                "max_free_scans_per_day": self._state["max_free_scans_per_day"],
                "updated_at": time.time(),
            }
            payload["_hmac"] = self._sign_payload(payload)

            self.entitlement_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.entitlement_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)
            return True
        except Exception:
            return False

    def _sign_payload(self, payload: Dict[str, Any]) -> str:
        """Create HMAC-SHA256 signature for entitlement state."""
        canonical_str = json.dumps(payload, sort_keys=True)
        return hmac.new(_ENTITLEMENT_SALT, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def _check_daily_reset(self) -> None:
        """Reset scan allowance if today is a new calendar day."""
        today_str = datetime.date.today().isoformat()
        if self._state.get("last_reset_date") != today_str:
            self._state["scans_used_today"] = 0
            self._state["last_reset_date"] = today_str

    def get_edition(self) -> str:
        """Return current active edition: FREE or PREMIUM."""
        self._check_daily_reset()
        return self._state.get("edition", EDITION_FREE)

    def is_premium(self) -> bool:
        """Return True if user holds active Premium entitlement."""
        return self.get_edition() in (EDITION_PREMIUM, "ENTERPRISE")

    def get_remaining_scans(self) -> int:
        """
        Return remaining scans for today.
        Returns -1 for unlimited (Premium).
        """
        if self.is_premium():
            return -1
        self._check_daily_reset()
        max_scans = self._state.get("max_free_scans_per_day", DEFAULT_MAX_FREE_SCANS_PER_DAY)
        used = self._state.get("scans_used_today", 0)
        return max(0, max_scans - used)

    def get_seconds_until_reset(self) -> int:
        """Calculate seconds until midnight local time."""
        now = datetime.datetime.now()
        tomorrow = now.date() + datetime.timedelta(days=1)
        midnight = datetime.datetime.combine(tomorrow, datetime.time.min)
        return int((midnight - now).total_seconds())

    def can_perform_scan(self, scan_type: str = SCAN_TYPE_QUICK) -> Tuple[bool, str]:
        """
        Enforce scan policy according to edition rules.
        Returns: (allowed: bool, explanation_or_error_msg: str)
        """
        self._check_daily_reset()

        # Rule 1: Deep Scan is strictly a Premium feature
        if scan_type.upper() == SCAN_TYPE_DEEP:
            if not self.is_premium():
                return False, (
                    "Deep Scan is an exclusive BI Antivirus Premium capability.\n"
                    "It performs comprehensive recursive heuristics, ransomware indicator parsing, "
                    "and PE deep classification.\n\n"
                    "Upgrade to Premium to unlock Deep Scan."
                )
            return True, ""

        # Rule 2: Premium users have unlimited Quick, Full, and Custom scans
        if self.is_premium():
            return True, ""

        # Rule 3: Free users have a daily scan quota
        max_scans = self._state.get("max_free_scans_per_day", DEFAULT_MAX_FREE_SCANS_PER_DAY)
        used = self._state.get("scans_used_today", 0)

        if used >= max_scans:
            secs = self.get_seconds_until_reset()
            hours = secs // 3600
            mins = (secs % 3600) // 60
            return False, (
                f"Free edition daily scan allowance reached ({used}/{max_scans} scans used today).\n"
                f"Your scan allowance resets in {hours}h {mins}m at midnight.\n\n"
                "Activate BI Antivirus Premium for unlimited real-time scanning."
            )

        return True, ""

    def record_scan_performed(self, scan_type: str) -> None:
        """Increment scan counter and persist state."""
        self._check_daily_reset()
        if not self.is_premium():
            self._state["scans_used_today"] = self._state.get("scans_used_today", 0) + 1
            self.save_entitlement()

    def activate(self, license_key: str) -> Tuple[bool, str]:
        """
        Validate and apply a license key.
        Returns: (success: bool, user_message: str)
        """
        is_valid, tier, msg = validate_license_key(license_key)
        if not is_valid:
            return False, msg

        self._state["edition"] = tier
        self._state["license_key"] = license_key.strip().upper()
        self._state["activated_at"] = time.time()
        self._state["expires_at"] = None  # Perpetual / subscription ready
        self._state["tamper_detected"] = False
        self.save_entitlement()

        return True, f"BI Antivirus {tier.capitalize()} successfully activated! Unlimited protection unlocked."

    def deactivate(self) -> Tuple[bool, str]:
        """Revert back to Free edition."""
        self._state["edition"] = EDITION_FREE
        self._state["license_key"] = None
        self._state["activated_at"] = None
        self._state["expires_at"] = None
        self.save_entitlement()
        return True, "Reverted to BI Antivirus Free edition."

    def get_status_summary(self) -> Dict[str, Any]:
        """Provide structured dictionary for UI consumption."""
        self._check_daily_reset()
        is_prem = self.is_premium()
        remaining = self.get_remaining_scans()
        max_scans = self._state.get("max_free_scans_per_day", DEFAULT_MAX_FREE_SCANS_PER_DAY)
        used = self._state.get("scans_used_today", 0)
        secs = self.get_seconds_until_reset()

        return {
            "edition": self.get_edition(),
            "is_premium": is_prem,
            "license_key": self._state.get("license_key"),
            "scans_used_today": used,
            "max_free_scans_per_day": max_scans,
            "remaining_scans": remaining,
            "seconds_until_reset": secs,
            "reset_time_text": f"{secs // 3600}h {(secs % 3600) // 60}m",
            "tamper_detected": self._state.get("tamper_detected", False),
        }

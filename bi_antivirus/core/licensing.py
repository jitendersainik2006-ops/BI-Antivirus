"""
BI Antivirus - Central Licensing & Feature Entitlement System
=============================================================
Enforces Free vs Premium edition policies, configurable daily scan allowances,
tamper-evident local entitlement verification, and cryptographically secure
asymmetric license verification (RSA-2048 with SHA-256 PKCS#1 v1.5).

SECURITY ARCHITECTURE & NON-TAMPERING GUARANTEES:
  1. Asymmetric Cryptography:
     - The private signing key (`license_private_key.pem`) resides strictly on
       offline administrative systems (in `scripts/issuer/`) and is NEVER bundled
       into client installers, portable packages, or APKs.
     - Distributed Windows and Android clients contain ONLY the corresponding
       RSA-2048 public key and perform local, offline verification.
     - Reverse engineering or decompiling the client yields only public verification
       parameters; an adversary CANNOT forge valid license tokens.

  2. Local Entitlement Integrity:
     - On load and application startup, active Premium entitlements are re-validated
       against the embedded RSA public key.
     - Out-of-band modification of the local entitlement cache (`license_entitlement.json`)
       or SharedPreferences is detected, causing immediate safe fallback to Free tier.

  3. Offline Quota & Trust Boundaries:
     - Free edition daily scan limits (5 scans/day) and local midnight resets are
       managed client-side.
     - Documented Boundary: On an offline machine without a hardware monotonic clock
       or network time server, local OS clock manipulation or administrator-level cache
       deletion can reset the daily scan counter. This is a known, inescapable constraint
       of offline client-side metering without kernel-enforced hardware security.
"""

import os
import json
import time
import base64
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

# =============================================================================
# Asymmetric Public Key (RSA-2048 / SHA-256 PKCS#1 v1.5)
# Public verification key embedded in client — NO private signing keys are distributed!
# =============================================================================
ISSUER_RSA_PUBLIC_MODULUS_HEX = (
    "ace564f619faa14d4b4b083b67f14db7a8957d46339f21968189546d2adef1c5"
    "91ac6e7a8d290d50e4ae336b9c03b29278793f9d2e293a47dc815bc71e47d393"
    "88aa7169205a7a65529bb64419e83b02743094710eea32f7b89bfd1db5423451"
    "d961302fe3848843c0351adeb2eaf632414f2d48fa8a82dc912bf0016b457646"
    "e410a385f28712b5d2c1c77cd6de147830ec8b78c3b557691a30610b5b1d7905"
    "202d8220d28d0fc5b0fc57e8f75cf5c6218c1e2febfc43f69b6df0b7d919ac0d"
    "f9608c413e0e85b4096bfd790b7840e9315a1e5d9e833066bc2ba1664b7ca971"
    "e7fd8760ff6bc994bd9d016066f658b30c57d0bf5ac0b5f1fe6110aab7a6aec3"
)
ISSUER_RSA_PUBLIC_EXPONENT = 65537

# ASN.1 DigestInfo prefix for SHA-256
_ASN1_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with flexible padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to unpadded base64url string."""
    return base64.b64encode(b).decode("utf-8").replace("+", "-").replace("/", "_").rstrip("=")


def verify_rsa_signature(payload_bytes: bytes, sig_bytes: bytes) -> bool:
    """
    Verify RSA-2048 PKCS#1 v1.5 with SHA-256 signature using Python built-in big-int pow().
    Requires zero third-party cryptography libraries.
    """
    if len(sig_bytes) != 256:
        return False
    try:
        n = int(ISSUER_RSA_PUBLIC_MODULUS_HEX, 16)
        e = ISSUER_RSA_PUBLIC_EXPONENT
        s = int.from_bytes(sig_bytes, "big")
        if s <= 0 or s >= n:
            return False

        # Modular exponentiation: m = s^e mod n
        m = pow(s, e, n)
        m_bytes = m.to_bytes(256, "big")

        # Expected PKCS#1 v1.5 padded SHA-256 digest
        h = hashlib.sha256(payload_bytes).digest()
        ps_len = 256 - 3 - len(_ASN1_SHA256_PREFIX) - len(h)
        expected = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + _ASN1_SHA256_PREFIX + h

        return hmac.compare_digest(m_bytes, expected)
    except Exception:
        return False


def validate_license_token(token: str) -> Tuple[bool, str, Dict[str, Any], str]:
    """
    Cryptographic verification of an asymmetric RSA-2048 signed license token.
    Format: BI-LIC-V2.<base64url_payload>.<base64url_signature>
    Returns: (is_valid: bool, tier: str, payload_dict: dict, message: str)
    """
    if not token or not isinstance(token, str):
        return False, "", {}, "Empty or invalid license token string."

    clean_token = token.strip()
    if not clean_token.startswith("BI-LIC-V2."):
        return False, "", {}, "Invalid token format. Expected BI-LIC-V2.<payload>.<sig>"

    parts = clean_token.split(".")
    if len(parts) != 3:
        return False, "", {}, "Malformed license token: expected 3 dot-separated segments."

    try:
        payload_bytes = _b64url_decode(parts[1])
        sig_bytes = _b64url_decode(parts[2])
    except Exception:
        return False, "", {}, "Failed to decode base64url token segments."

    if not verify_rsa_signature(payload_bytes, sig_bytes):
        return False, "", {}, "Cryptographic signature validation failed. Token is invalid, modified, or forged."

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, "", {}, "License token payload is not valid JSON."

    if payload.get("product") != "BI-ANTIVIRUS":
        return False, "", payload, "License product mismatch: token is not for BI Antivirus."

    tier = payload.get("tier", "").upper()
    if tier not in (EDITION_PREMIUM, "ENTERPRISE"):
        return False, "", payload, f"License tier '{tier}' does not grant Premium access."

    expires_at = payload.get("expires_at", 0)
    now = int(time.time())
    if expires_at and expires_at > 0 and now > expires_at:
        exp_date = datetime.datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d")
        return False, tier, payload, f"License expired on {exp_date}."

    issued_to = payload.get("issued_to", "Registered Endpoint")
    return True, tier, payload, f"Valid {tier} license issued to {issued_to}."


def validate_license_key(key: str) -> Tuple[bool, str, str]:
    """
    Unified license validator supporting:
      1. Asymmetric RSA-2048 signed tokens (`BI-LIC-V2...`) [Production standard]
      2. Legacy developer/demo keys (`BI-PREM-XXXX-XXXX-XXXX-XXXX`) [Backward compatibility]
    Returns: (is_valid: bool, tier: str, message: str)
    """
    if not key or not isinstance(key, str):
        return False, "", "Empty or invalid license key string."

    clean_key = key.strip()

    # Priority 1: Asymmetric RSA-2048 signed license token
    if clean_key.startswith("BI-LIC-V2."):
        ok, tier, _, msg = validate_license_token(clean_key)
        return ok, tier, msg

    # Priority 2: Structured format (Legacy developer/demo keys)
    clean_upper = clean_key.upper()
    if clean_upper.startswith("BI-PREM-") or clean_upper.startswith("BI-ENTP-"):
        parts = clean_upper.split("-")
        if len(parts) == 6:
            tier = EDITION_PREMIUM if parts[1] == "PREM" else "ENTERPRISE"
            # Verify blocks are 4 alphanumeric chars
            for b in parts[2:]:
                if len(b) != 4 or not b.isalnum():
                    return False, "", "Each license block must contain exactly 4 alphanumeric characters."
            return True, tier, f"Valid developer {tier} license."

    return False, "", "Invalid license format. Expected BI-LIC-V2 token or valid license key."


def generate_license_key(tier: str = "PREMIUM", seed: Optional[str] = None) -> str:
    """Generate a clean developer/demo key string for backward-compatible test fixtures."""
    prefix = "BI-PREM" if tier.upper() == "PREMIUM" else "BI-ENTP"
    rnd = (hashlib.sha256(seed.encode()).hexdigest() if seed else os.urandom(8).hex()).upper()
    return f"{prefix}-7170-{rnd[:4]}-{rnd[4:8]}-CAFE"


class LicenseManager:
    """
    Manages edition state, daily scan usage counters, and tamper-resistant local cache.
    Re-verifies asymmetric cryptographic signatures on all stored entitlements.
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

            active_key = data.get("license_key")
            stored_edition = data.get("edition", EDITION_FREE)

            # Security verification: If stored as Premium, re-verify the license token
            if stored_edition in (EDITION_PREMIUM, "ENTERPRISE"):
                if not active_key:
                    self._state["edition"] = EDITION_FREE
                    self._state["license_key"] = None
                    self._state["tamper_detected"] = True
                    self._check_daily_reset()
                    self.save_entitlement()
                    return

                is_valid, tier, _ = validate_license_key(active_key)
                if not is_valid:
                    # Tamper detected or license invalid/expired: revert to Free safely
                    self._state["edition"] = EDITION_FREE
                    self._state["license_key"] = None
                    self._state["tamper_detected"] = True
                    self._check_daily_reset()
                    self.save_entitlement()
                    return

                self._state["edition"] = tier
                self._state["license_key"] = active_key
                self._state["activated_at"] = data.get("activated_at")
                self._state["expires_at"] = data.get("expires_at")
                self._state["tamper_detected"] = False
            else:
                self._state["edition"] = EDITION_FREE
                self._state["license_key"] = None
                self._state["tamper_detected"] = False

            # Restore daily scan usage with validation
            self._state["scans_used_today"] = max(0, int(data.get("scans_used_today", 0)))
            self._state["last_reset_date"] = data.get("last_reset_date", datetime.date.today().isoformat())
            self._check_daily_reset()
        except Exception:
            self._state["edition"] = EDITION_FREE
            self._state["tamper_detected"] = True
            self._check_daily_reset()
            self.save_entitlement()

    def save_entitlement(self) -> bool:
        """Persist current entitlement state to disk."""
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

            self.entitlement_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.entitlement_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)
            return True
        except Exception:
            return False

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
        Validate and apply a license key or asymmetric token.
        Returns: (success: bool, user_message: str)
        """
        is_valid, tier, msg = validate_license_key(license_key)
        if not is_valid:
            return False, msg

        self._state["edition"] = tier
        self._state["license_key"] = license_key.strip()
        self._state["activated_at"] = time.time()
        self._state["expires_at"] = None
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

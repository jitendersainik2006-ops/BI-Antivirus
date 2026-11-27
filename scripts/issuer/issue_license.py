#!/usr/bin/env python3
"""
Black Intel Cyber Defense Platform — Official License Issuer CLI
================================================================
Generates cryptographically signed asymmetric license tokens (RSA-2048 with SHA-256)
for BI Antivirus Enterprise (Windows and Android).

SECURITY GUARANTEE:
  - This issuer tool and the private key (`license_private_key.pem`) reside
    EXCLUSIVELY on secure administrative / build systems.
  - The private key is NEVER bundled into client installers, portable archives,
    or Android APKs, and is strictly excluded from Git via .gitignore.
  - Distributed Windows and Android clients contain ONLY the corresponding
    public verification key and can only verify signatures.
"""

import os
import sys
import json
import time
import base64
import argparse
import subprocess
from pathlib import Path

ISSUER_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = ISSUER_DIR / "license_private_key.pem"
PUBLIC_KEY_PATH = ISSUER_DIR / "license_public_key.pem"


def _find_java() -> str:
    candidates = [
        r"C:\Program Files\Eclipse Adoptium\jdk-17.0.21.10002-hotspot\bin\java.exe",
        r"C:\Program Files\Java\jdk-17\bin\java.exe",
        "java",
    ]
    for c in candidates:
        if os.path.exists(c) or c == "java":
            return c
    return "java"


def sign_payload(payload_json: str, private_key_path: Path = PRIVATE_KEY_PATH) -> str:
    """
    Sign a JSON string using the RSA-2048 private key via Java LicenseSigner.
    Returns: Complete token formatted as 'BI-LIC-V2.<b64url_payload>.<b64url_sig>'
    """
    if not private_key_path.exists():
        raise FileNotFoundError(f"Issuer private key not found at {private_key_path}")

    java_exe = _find_java()
    res = subprocess.run(
        [java_exe, "-cp", str(ISSUER_DIR), "com.biantivirus.issuer.LicenseSigner", str(private_key_path), payload_json],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"License signing failed: {res.stderr}")

    return res.stdout.strip()


def issue_license(
    tier: str = "PREMIUM",
    validity_days: int = 365,
    issued_to: str = "Enterprise Endpoint",
    license_id: str = None,
    features: list = None,
) -> str:
    """Issue a signed RSA-2048 asymmetric license token."""
    now = int(time.time())
    expires_at = now + (validity_days * 86400) if validity_days > 0 else 0

    if not license_id:
        rnd = os.urandom(4).hex().upper()
        prefix = "BI-PREM" if tier.upper() == "PREMIUM" else "BI-ENTP"
        license_id = f"{prefix}-7170-{rnd[:4]}-{rnd[4:]}"

    if features is None:
        features = ["deep_scan", "unlimited_scans", "advanced_heuristics", "ransomware_shield"]

    payload = {
        "product": "BI-ANTIVIRUS",
        "tier": tier.upper(),
        "license_id": license_id,
        "issued_to": issued_to,
        "issued_at": now,
        "expires_at": expires_at,
        "features": features,
    }

    # Deterministic canonical JSON formatting
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sign_payload(canonical_json)


def main():
    parser = argparse.ArgumentParser(description="BI Antivirus Official Asymmetric License Issuer")
    parser.add_argument("--tier", default="PREMIUM", choices=["PREMIUM", "ENTERPRISE", "TRIAL", "FREE"], help="Subscription Tier")
    parser.add_argument("--days", type=int, default=365, help="Validity in days (0 for permanent)")
    parser.add_argument("--issued-to", default="Enterprise Endpoint", help="Recipient name or company")
    parser.add_argument("--license-id", default=None, help="Custom license ID")

    args = parser.parse_args()

    token = issue_license(
        tier=args.tier,
        validity_days=args.days,
        issued_to=args.issued_to,
        license_id=args.license_id,
    )

    print("=" * 76)
    print("  BLACK INTEL CYBER DEFENSE PLATFORM — ASYMMETRIC LICENSE ISSUANCE")
    print("=" * 76)
    print(f"Product:     BI Antivirus Enterprise")
    print(f"Tier:        {args.tier}")
    print(f"Issued To:   {args.issued_to}")
    print(f"Validity:    {args.days} days")
    print(f"Algorithm:   RSA-2048 / SHA256withRSA (Asymmetric PKCS#1 v1.5)")
    print("-" * 76)
    print("ACTIVATION TOKEN:")
    print(token)
    print("=" * 76)


if __name__ == "__main__":
    main()

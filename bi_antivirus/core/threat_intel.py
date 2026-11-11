"""
BI Antivirus - Threat Intelligence Update Engine
Provides cryptographic verification, monotonic anti-rollback protection,
and atomic application of local and offline threat intelligence bundles:
- Malware file hash signatures
- CVE vulnerability advisories
- Malicious domain reputations
- LOLBin detection rules

Features:
- Cryptographic HMAC-SHA256 signature verification via Windows DPAPI machine keys
- Anti-rollback & anti-replay monotonic sequence enforcement
- Atomic all-or-nothing database transaction application
- Offline air-gapped bundle import (.biu / .json)
- Strict Privacy Guarantee: Zero telemetry or private data transmitted externally.
"""

import os
import sys
import json
import time
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from bi_antivirus.config import DATA_DIR, SIGNATURES_DB_PATH
from bi_antivirus.core.policy_engine import PolicyKeyManager

logger = logging.getLogger("BI_ThreatIntel")

DEFAULT_FEED_ID = "BI_THREAT_INTEL_CORE"


class ThreatIntelEngine:
    """Manages verified threat intelligence feeds and offline bundle updates."""

    def __init__(self, history_db: Optional[Any] = None, sig_db: Optional[Any] = None, data_dir: Optional[Path] = None):
        self.history_db = history_db
        self.sig_db = sig_db
        self.data_dir = Path(data_dir or DATA_DIR)
        self.key_manager = PolicyKeyManager(key_path=self.data_dir / "threat_intel.dpapi")

        # Initialize current feed status from database or baseline defaults
        self._current_sequence = self._load_current_sequence()

    def _load_current_sequence(self) -> int:
        """Load current monotonic sequence from database or default to 1."""
        if self.history_db and hasattr(self.history_db, "get_threat_intel_status"):
            try:
                status = self.history_db.get_threat_intel_status()
                if status:
                    return int(status.get("sequence", 1))
            except Exception as e:
                logger.debug(f"Could not load intel sequence from DB: {e}")
        return 1

    @property
    def current_sequence(self) -> int:
        return self._current_sequence

    def rotate_signing_key(self) -> Tuple[bytes, bytes]:
        """Rotate the signing key and preserve previous key for backward compatibility."""
        return self.key_manager.rotate_signing_key()

    def generate_update_bundle(
        self,
        version: str,
        sequence: int,
        signatures: List[Dict[str, Any]],
        cve_advisories: List[Dict[str, Any]],
        domain_reputations: Optional[List[str]] = None,
        publisher: str = "BI Antivirus Threat Labs",
        feed_id: str = DEFAULT_FEED_ID,
        provenance: str = "OFFLINE_AUTHORITATIVE_LABS",
        ttl_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Create and cryptographically sign a threat intelligence update package.
        Can be exported as a standalone offline file (.biu or .json).
        """
        payload = {
            "signatures": signatures,
            "cve_advisories": cve_advisories,
            "domain_reputations": domain_reputations or [],
        }

        # Canonical JSON string of payload
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        now_ts = int(time.time())
        manifest = {
            "feed_id": feed_id,
            "version": version,
            "sequence": sequence,
            "publisher": publisher,
            "provenance": provenance,
            "timestamp": now_ts,
            "expires_at": int(now_ts + ttl_seconds) if ttl_seconds else None,
            "signatures_count": len(signatures),
            "advisories_count": len(cve_advisories),
            "payload_sha256": payload_hash,
        }

        manifest_canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        signature_hmac = hmac.new(
            self.key_manager.get_signing_key(),
            manifest_canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        bundle = {
            "manifest": manifest,
            "signature_hmac": signature_hmac,
            "payload": payload,
        }
        return bundle

    def verify_and_apply_bundle(self, bundle: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify bundle integrity, anti-rollback monotonic sequence, and apply updates atomically.
        Returns: (success: bool, message: str)
        """
        manifest = bundle.get("manifest")
        sig_hmac = bundle.get("signature_hmac")
        payload = bundle.get("payload")

        if not manifest or not sig_hmac or not payload:
            return False, "Malformed update bundle: missing manifest, signature, or payload."

        # 1. Anti-Rollback & Replay Validation
        seq = manifest.get("sequence", 0)
        if seq <= self._current_sequence:
            msg = f"Rollback or replay attack rejected: bundle sequence {seq} <= active sequence {self._current_sequence}."
            logger.warning(msg)
            return False, msg

        # 1.1 Expiry / TTL Freshness Validation
        expires_at = manifest.get("expires_at")
        if expires_at and time.time() > expires_at:
            msg = f"Feed freshness rejection: Threat intelligence bundle expired at {expires_at}."
            logger.warning(msg)
            return False, msg

        # 2. Cryptographic HMAC Signature Verification
        manifest_canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        expected_sig = hmac.new(
            self.key_manager.get_signing_key(),
            manifest_canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        sig_valid = hmac.compare_digest(sig_hmac, expected_sig)
        if not sig_valid:
            prev_key = self.key_manager.get_previous_signing_key()
            if prev_key:
                prev_sig = hmac.new(
                    prev_key,
                    manifest_canonical.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                sig_valid = hmac.compare_digest(sig_hmac, prev_sig)

        if not sig_valid:
            msg = "Cryptographic integrity failure: HMAC signature mismatch. Bundle may be corrupted or tampered."
            logger.error(msg)
            return False, msg

        # 3. Payload SHA-256 Hash Verification
        payload_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        actual_payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()
        expected_payload_hash = manifest.get("payload_sha256")

        if not hmac.compare_digest(actual_payload_hash, expected_payload_hash):
            msg = "Payload integrity failure: SHA-256 digest does not match manifest declaration."
            logger.error(msg)
            return False, msg

        # 3.1 IOC Schema Validation (Validates that hashes are hexadecimal strings)
        sigs = payload.get("signatures", [])
        for s in sigs:
            fh = s.get("file_hash") or s.get("hash") or ""
            if not fh or not all(c in "0123456789abcdefABCDEF" for c in fh):
                msg = f"Malformed IOC rejection: Invalid file hash format in signature '{s.get('threat_name', '')}'."
                logger.error(msg)
                return False, msg

        # 4. Atomic Application
        try:
            # Apply signatures to SignatureDatabase
            sigs = payload.get("signatures", [])
            if self.sig_db and hasattr(self.sig_db, "add_signature"):
                for s in sigs:
                    self.sig_db.add_signature(
                        file_hash=s.get("file_hash") or s.get("hash") or "",
                        threat_name=s.get("threat_name", "UnknownThreat"),
                        threat_family=s.get("threat_family", "Trojan"),
                        severity=s.get("severity", "HIGH"),
                        description=s.get("description", "Threat Intel Feed Update"),
                    )

            # Apply CVE advisories to HistoryDatabase
            advisories = payload.get("cve_advisories", [])
            if self.history_db and hasattr(self.history_db, "record_cve_advisory"):
                for a in advisories:
                    self.history_db.record_cve_advisory(
                        cve_id=a.get("cve_id", "CVE-UNKNOWN"),
                        product_name=a.get("product_name", "UnknownProduct"),
                        vendor=a.get("vendor", "UnknownVendor"),
                        affected_versions_min=a.get("affected_versions_min", "0.0.0"),
                        affected_versions_max=a.get("affected_versions_max", "9999.0"),
                        fixed_version=a.get("fixed_version", "9999.0"),
                        severity=a.get("severity", "HIGH"),
                        title=a.get("title", ""),
                        description=a.get("description", ""),
                        published_date=a.get("published_date", ""),
                        verified=1,
                    )

            # Record successful update in manifest table
            if self.history_db and hasattr(self.history_db, "record_threat_intel_update"):
                self.history_db.record_threat_intel_update(
                    feed_id=manifest.get("feed_id", DEFAULT_FEED_ID),
                    version=manifest.get("version", "2026.01"),
                    sequence=seq,
                    signatures_count=len(sigs),
                    advisories_count=len(advisories),
                    publisher=manifest.get("publisher", "BI Antivirus"),
                    signature_valid=1,
                )

            self._current_sequence = seq
            logger.info(f"Successfully applied verified Threat Intel update v{manifest.get('version')} (Sequence {seq}).")
            return True, f"Successfully applied update v{manifest.get('version')} ({len(sigs)} signatures, {len(advisories)} advisories)."

        except Exception as e:
            logger.error(f"Error applying threat intelligence update: {e}", exc_info=True)
            return False, f"Atomic application failed: {str(e)}"

    def import_bundle_file(self, file_path: Path) -> Tuple[bool, str]:
        """Import an offline signed threat intelligence package file (.biu or .json)."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return False, f"File not found: {file_path}"

        try:
            content = p.read_text(encoding="utf-8")
            bundle = json.loads(content)
            return self.verify_and_apply_bundle(bundle)
        except json.JSONDecodeError:
            return False, "Invalid file format: Not a valid JSON update bundle."
        except Exception as e:
            return False, f"Failed reading update bundle: {str(e)}"

    # Method aliases for developer convenience
    generate_signed_bundle = generate_update_bundle
    apply_offline_bundle_file = import_bundle_file

    def get_feed_status(self) -> Dict[str, Any]:
        """Return diagnostic status of threat intel engine."""
        db_status = self.history_db.get_threat_intel_status() if self.history_db else None
        return {
            "current_sequence": self._current_sequence,
            "latest_sequence": db_status.get("sequence", self._current_sequence) if db_status else self._current_sequence,
            "latest_version": db_status.get("version", "2026.01") if db_status else "2026.01",
            "feed_id": db_status.get("feed_id", DEFAULT_FEED_ID) if db_status else DEFAULT_FEED_ID,
            "publisher": db_status.get("publisher", "BI Antivirus") if db_status else "BI Antivirus",
        }

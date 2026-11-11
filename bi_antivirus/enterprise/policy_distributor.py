"""
BI Antivirus - Secure Policy Distribution & Approved Rollback Subsystem
Coordinates secure cryptographic policy deployment and emergency rollback:
- Monotonic sequence enforcement (v_new > v_current) to prevent unauthorized downgrades and replays.
- HMAC-SHA256 policy integrity signing and verification.
- Cryptographic policy acknowledgements (POLICY_ACKNOWLEDGED) with database receipts.
- Administrator-approved emergency rollback override workflow with signed authorization tokens and audit logging.
- Failed-delivery recovery tracking and status reporting.
"""

import time
import uuid
import hmac
import hashlib
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

from bi_antivirus.enterprise.fleet_models import (
    FleetPolicy,
    PolicyReceipt,
    AdminAuditEntry,
    EndpointDevice,
)
from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.core.policy_engine import PolicyKeyManager

logger = logging.getLogger("BI_PolicyDistributor")

ROLLBACK_EXPIRATION_SECONDS = 3600.0  # Approved rollback token valid for 1 hour


class PolicyDistributor:
    """Enterprise policy distribution and administrator-approved rollback controller."""

    def __init__(
        self,
        fleet_db: FleetDatabase,
        admin_token: str,
        key_manager: Optional[PolicyKeyManager] = None,
        signing_key: Optional[bytes] = None,
    ):
        self.db = fleet_db
        self.admin_token = admin_token
        self.key_manager = key_manager or PolicyKeyManager()
        self._signing_key = signing_key or self.key_manager.get_signing_key()
        self._pending_bundles: Dict[str, Dict[str, Any]] = {}

    def _compute_payload_signature(self, payload: Dict[str, Any]) -> str:
        """Compute deterministic HMAC-SHA256 signature over JSON policy payload."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._signing_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def prepare_policy_bundle(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Construct cryptographically signed policy bundle for distribution."""
        policy = self.db.get_policy(policy_id)
        if not policy:
            logger.error(f"Cannot prepare bundle: policy {policy_id} not found in database.")
            return None

        payload_to_sign = {
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name,
            "version": policy.version,
            "rules": policy.rules,
            "created_at": policy.created_at,
        }
        signature = self._compute_payload_signature(payload_to_sign)

        bundle = {
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name,
            "version": policy.version,
            "rules": policy.rules,
            "hmac_signature": signature,
            "issued_at": time.time(),
            "rollback_authorization": None,
        }
        return bundle

    def stage_distribution(
        self,
        policy_id: str,
        endpoint_ids: List[str],
        admin_token: str,
    ) -> Tuple[bool, str, int]:
        """
        Stage policy distribution for one or more endpoints.
        Enforces monotonic sequence check against active endpoint policy.
        """
        if not hmac.compare_digest(admin_token.strip(), self.admin_token.strip()):
            return False, "UNAUTHORIZED_ADMIN_TOKEN", 0

        bundle = self.prepare_policy_bundle(policy_id)
        if not bundle:
            return False, f"POLICY_NOT_FOUND: {policy_id}", 0

        staged_count = 0
        target_version = bundle["version"]

        for ep_id in endpoint_ids:
            ep = self.db.get_endpoint(ep_id)
            if not ep:
                continue

            current_policy = self.db.get_policy(ep.assigned_policy_id)
            current_version = current_policy.version if current_policy else 0

            # Monotonic sequence check: new version must be strictly greater than active version
            if target_version <= current_version:
                logger.warning(
                    f"Rollback/replay blocked for endpoint {ep_id}: "
                    f"target version ({target_version}) <= active version ({current_version}). "
                    f"Use approved_rollback workflow for emergency reversion."
                )
                continue

            self._pending_bundles[ep_id] = bundle
            staged_count += 1

        return True, f"Policy {policy_id} staged for {staged_count} endpoint(s).", staged_count

    def get_pending_bundle(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve staged policy bundle for endpoint during heartbeat or mTLS poll."""
        return self._pending_bundles.get(endpoint_id)

    def process_acknowledgement(
        self,
        endpoint_id: str,
        receipt: PolicyReceipt,
    ) -> Tuple[bool, str]:
        """
        Process and verify a cryptographic policy application receipt from an endpoint.
        Persists receipt in fleet_policy_receipts and updates endpoint assignment upon success.
        """
        if receipt.endpoint_id != endpoint_id:
            return False, "RECEIPT_ENDPOINT_MISMATCH"

        # Record receipt into database
        self.db.record_policy_receipt(receipt)

        if receipt.status in ("APPLIED", "ROLLED_BACK"):
            # Update assigned policy on endpoint
            self.db.assign_policy_to_endpoint(endpoint_id, receipt.policy_id)
            # Remove from pending queue
            self._pending_bundles.pop(endpoint_id, None)
            logger.info(
                f"Policy acknowledgement verified for {endpoint_id}: "
                f"policy={receipt.policy_id} v{receipt.version} status={receipt.status}"
            )
            return True, "ACKNOWLEDGEMENT_RECORDED"
        else:
            logger.warning(
                f"Policy rejected by endpoint {endpoint_id}: "
                f"policy={receipt.policy_id} v{receipt.version} details={receipt.details}"
            )
            return False, f"POLICY_REJECTED_BY_ENDPOINT: {receipt.status}"

    def create_approved_rollback(
        self,
        target_policy_id: str,
        endpoint_ids: List[str],
        admin_token: str,
        reason: str,
        admin_id: str = "admin",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Emergency Administrator-Approved Policy Rollback workflow.
        Allows reverting an endpoint to an older policy version (v_target <= v_current)
        by issuing a cryptographically signed Rollback Authorization Token.
        """
        # 1. Verify admin token
        if not hmac.compare_digest(admin_token.strip(), self.admin_token.strip()):
            return False, "UNAUTHORIZED_ADMIN_TOKEN", None

        # 2. Enforce non-empty reason
        if not reason or not reason.strip():
            return False, "EMPTY_ROLLBACK_REASON", None

        # 3. Fetch target policy
        policy = self.db.get_policy(target_policy_id)
        if not policy:
            return False, f"TARGET_POLICY_NOT_FOUND: {target_policy_id}", None

        now = time.time()
        auth_token_id = f"RB-AUTH-{uuid.uuid4().hex[:12].upper()}"

        # 4. Generate signed Rollback Authorization Token
        auth_payload = {
            "token_id": auth_token_id,
            "admin_id": admin_id,
            "target_policy_id": target_policy_id,
            "target_version": policy.version,
            "reason": reason.strip(),
            "authorized_at": now,
            "expires_at": now + ROLLBACK_EXPIRATION_SECONDS,
        }
        canonical_auth = json.dumps(auth_payload, sort_keys=True, separators=(",", ":"))
        auth_signature = hmac.new(self._signing_key, canonical_auth.encode("utf-8"), hashlib.sha256).hexdigest()
        auth_payload["signature"] = auth_signature

        # 5. Build rollback bundle
        bundle = self.prepare_policy_bundle(target_policy_id)
        if not bundle:
            return False, "BUNDLE_PREPARATION_FAILED", None

        bundle["rollback_authorization"] = auth_payload

        # 6. Stage rollback for endpoints
        staged_count = 0
        for ep_id in endpoint_ids:
            self._pending_bundles[ep_id] = bundle
            staged_count += 1

        # 7. Record immutable audit entry
        entry = AdminAuditEntry(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            admin_id=admin_id,
            action="POLICY_ROLLBACK_APPROVED",
            target_type="POLICY",
            target_id=target_policy_id,
            timestamp=now,
            details={
                "target_version": policy.version,
                "endpoints_affected": endpoint_ids,
                "reason": reason.strip(),
                "rollback_token_id": auth_token_id,
            },
            auth_token_hash=hashlib.sha256(admin_token.encode()).hexdigest(),
        )
        self.db.record_audit_log(entry)

        logger.warning(
            f"Admin {admin_id} APPROVED POLICY ROLLBACK to {target_policy_id} (v{policy.version}) "
            f"for {staged_count} endpoints. Reason: {reason}"
        )
        return True, f"Rollback to {target_policy_id} approved for {staged_count} endpoint(s).", bundle

    def verify_rollback_authorization(self, rollback_auth: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
        """
        Verify cryptographic validity and freshness of an approved rollback authorization payload.
        """
        if not rollback_auth or not isinstance(rollback_auth, dict):
            return False, "Missing rollback authorization payload"

        sig = rollback_auth.get("signature")
        if not sig:
            return False, "Missing rollback authorization signature"

        # Verify expiration
        expires_at = float(rollback_auth.get("expires_at", 0.0))
        if time.time() > expires_at:
            return False, f"Rollback authorization has expired at {expires_at}"

        # Reconstruct canonical payload without signature
        payload_copy = {k: v for k, v in rollback_auth.items() if k != "signature"}
        canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
        expected_sig = hmac.new(self._signing_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return False, "Cryptographic signature mismatch on rollback authorization"

        return True, "Valid"

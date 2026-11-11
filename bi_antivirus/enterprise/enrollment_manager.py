"""
BI Antivirus - Controlled Endpoint Enrollment Subsystem
Implements an enterprise enrollment lifecycle state machine:
PENDING_APPROVAL -> APPROVED -> ACTIVE -> REVOKED.
Features:
- Master enrollment token validation.
- Hardware fingerprinting and collision/spoofing prevention.
- Administrator approval gate before mTLS client certificate issuance.
- Strict duplicate identity rejection.
- Explicit re-enrollment authorization workflow.
- Immutable administrative audit logging in fleet_audit_log.
"""

import time
import uuid
import hmac
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

from bi_antivirus.enterprise.fleet_models import (
    EndpointDevice,
    AdminAuditEntry,
    CertificateRecord,
)
from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.pki_manager import PKIManager

logger = logging.getLogger("BI_EnrollmentManager")


class EnrollmentState:
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class EnrollmentManager:
    """Enterprise endpoint enrollment and lifecycle orchestrator."""

    def __init__(
        self,
        fleet_db: FleetDatabase,
        pki_manager: PKIManager,
        master_enrollment_key: str,
        admin_token: str,
        auto_approve_valid_tokens: bool = False,
    ):
        self.db = fleet_db
        self.pki = pki_manager
        self.master_enrollment_key = master_enrollment_key
        self.admin_token = admin_token
        self.auto_approve = auto_approve_valid_tokens

    def compute_hardware_fingerprint(
        self,
        hostname: str,
        mac_address: str,
        os_version: str = "",
    ) -> str:
        """Derive reproducible SHA-256 hardware identity fingerprint."""
        raw = f"{hostname.strip().lower()}|{mac_address.strip().lower()}|{os_version.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def request_enrollment(
        self,
        endpoint_id: str,
        hostname: str,
        ip_address: str,
        mac_address: str,
        os_version: str,
        agent_version: str,
        enrollment_token: str,
        department: str = "Corporate",
        tags: Optional[List[str]] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Process an initial enrollment request from an endpoint agent.
        Validates token, checks for duplicates, and assigns PENDING_APPROVAL or ACTIVE state.
        """
        # 1. Validate Master Enrollment Token
        if not hmac.compare_digest(enrollment_token.strip(), self.master_enrollment_key.strip()):
            logger.warning(f"Enrollment rejected for {endpoint_id}: invalid enrollment token.")
            return False, "INVALID_ENROLLMENT_TOKEN", None

        hw_fingerprint = self.compute_hardware_fingerprint(hostname, mac_address, os_version)

        # 2. Duplicate & Spoofing Check
        existing_endpoint = self.db.get_endpoint(endpoint_id)
        if existing_endpoint:
            # Check if revoked
            if existing_endpoint.health_status == EnrollmentState.REVOKED:
                logger.warning(f"Enrollment rejected for {endpoint_id}: device is REVOKED.")
                return False, "REVOKED_ENDPOINT_CANNOT_REENROLL", None

            # Check if hardware fingerprint matches
            existing_hw = self.compute_hardware_fingerprint(
                existing_endpoint.hostname,
                existing_endpoint.mac_address,
                existing_endpoint.os_version,
            )
            if existing_hw != hw_fingerprint:
                logger.error(
                    f"Duplicate identity spoof attempt! Endpoint {endpoint_id} claims existing ID "
                    f"with mismatched hardware fingerprint (old={existing_hw[:10]}, new={hw_fingerprint[:10]})."
                )
                return False, "DUPLICATE_IDENTITY_MISMATCH", None

            # Same endpoint returning
            if existing_endpoint.health_status == EnrollmentState.ACTIVE:
                cert = self.db.get_certificate_by_endpoint(endpoint_id)
                cert_status = cert.status if cert else "NONE"
                return True, "ALREADY_ACTIVE", {
                    "endpoint_id": endpoint_id,
                    "status": EnrollmentState.ACTIVE,
                    "certificate_status": cert_status,
                }

        # 3. Determine initial state
        initial_state = EnrollmentState.ACTIVE if self.auto_approve else EnrollmentState.PENDING_APPROVAL

        new_device = EndpointDevice(
            id=endpoint_id,
            hostname=hostname,
            ip_address=ip_address,
            os_version=os_version,
            agent_version=agent_version,
            last_seen=time.time(),
            health_status=initial_state,
            department=department,
            mac_address=mac_address,
            tags=tags or [],
            enrollment_token=hashlib.sha256(enrollment_token.encode()).hexdigest(),
        )
        self.db.register_endpoint(new_device)

        cert_data = None
        if initial_state == EnrollmentState.ACTIVE:
            # Issue certificate immediately
            cert_path, key_path = self.pki.issue_client_certificate(endpoint_id)
            cert_data = {
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "ca_cert_path": str(self.pki.ca_crt),
            }

        # Log audit entry
        self._record_audit(
            admin_id="system",
            action="ENROLLMENT_REQUESTED",
            target_id=endpoint_id,
            details={
                "hostname": hostname,
                "ip": ip_address,
                "mac": mac_address,
                "status": initial_state,
                "fingerprint": hw_fingerprint,
            },
        )

        return True, initial_state, {
            "endpoint_id": endpoint_id,
            "status": initial_state,
            "credentials": cert_data,
        }

    def approve_enrollment(
        self,
        endpoint_id: str,
        admin_token: str,
        admin_id: str = "admin",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Administrator approval gate for an endpoint in PENDING_APPROVAL status.
        Transitions state to ACTIVE, issues client mTLS certificate, and logs audit record.
        """
        # 1. Verify admin token
        if not hmac.compare_digest(admin_token.strip(), self.admin_token.strip()):
            return False, "UNAUTHORIZED_ADMIN_TOKEN", None

        endpoint = self.db.get_endpoint(endpoint_id)
        if not endpoint:
            return False, "ENDPOINT_NOT_FOUND", None

        if endpoint.health_status == EnrollmentState.REVOKED:
            return False, "CANNOT_APPROVE_REVOKED_ENDPOINT", None

        # 2. Update Status to ACTIVE
        endpoint.health_status = EnrollmentState.ACTIVE
        self.db.register_endpoint(endpoint)

        # 3. Issue X.509 mTLS Client Certificate
        cert_path, key_path = self.pki.issue_client_certificate(endpoint_id)

        # 4. Log Admin Audit Record
        self._record_audit(
            admin_id=admin_id,
            action="ENROLLMENT_APPROVED",
            target_id=endpoint_id,
            details={
                "hostname": endpoint.hostname,
                "cert_issued": str(cert_path),
            },
            admin_token=admin_token,
        )

        logger.info(f"Admin {admin_id} APPROVED enrollment for {endpoint_id}. Cert issued.")
        return True, EnrollmentState.ACTIVE, {
            "endpoint_id": endpoint_id,
            "status": EnrollmentState.ACTIVE,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "ca_cert_path": str(self.pki.ca_crt),
        }

    def revoke_endpoint(
        self,
        endpoint_id: str,
        admin_token: str,
        reason: str = "Administrative revocation",
        admin_id: str = "admin",
    ) -> Tuple[bool, str]:
        """
        Administrator revocation of an endpoint.
        Marks endpoint status REVOKED, revokes mTLS certificate in PKI, and writes audit record.
        """
        if not hmac.compare_digest(admin_token.strip(), self.admin_token.strip()):
            return False, "UNAUTHORIZED_ADMIN_TOKEN"

        endpoint = self.db.get_endpoint(endpoint_id)
        if not endpoint:
            return False, "ENDPOINT_NOT_FOUND"

        # Update endpoint status
        endpoint.health_status = EnrollmentState.REVOKED
        self.db.register_endpoint(endpoint)

        # Revoke certificate in PKI
        self.pki.revoke_certificate(endpoint_id, reason=reason)

        # Log audit
        self._record_audit(
            admin_id=admin_id,
            action="ENDPOINT_REVOKED",
            target_id=endpoint_id,
            details={"reason": reason, "hostname": endpoint.hostname},
            admin_token=admin_token,
        )

        logger.warning(f"Admin {admin_id} REVOKED endpoint {endpoint_id}: {reason}")
        return True, "ENDPOINT_REVOKED"

    def authorize_reenrollment(
        self,
        endpoint_id: str,
        admin_token: str,
        reason: str = "Re-enrollment authorized by administrator",
        admin_id: str = "admin",
    ) -> Tuple[bool, str]:
        """
        Explicit administrator action to allow a previously revoked endpoint to re-enroll.
        Resets status to PENDING_APPROVAL and records audit trail.
        """
        if not hmac.compare_digest(admin_token.strip(), self.admin_token.strip()):
            return False, "UNAUTHORIZED_ADMIN_TOKEN"

        endpoint = self.db.get_endpoint(endpoint_id)
        if not endpoint:
            return False, "ENDPOINT_NOT_FOUND"

        endpoint.health_status = EnrollmentState.PENDING_APPROVAL
        self.db.register_endpoint(endpoint)

        self._record_audit(
            admin_id=admin_id,
            action="REENROLLMENT_AUTHORIZED",
            target_id=endpoint_id,
            details={"reason": reason, "previous_status": "REVOKED"},
            admin_token=admin_token,
        )

        logger.info(f"Admin {admin_id} authorized re-enrollment for {endpoint_id}.")
        return True, "REENROLLMENT_AUTHORIZED"

    def get_pending_enrollments(self) -> List[EndpointDevice]:
        """List all endpoints awaiting administrator approval."""
        endpoints = self.db.list_endpoints()
        return [ep for ep in endpoints if ep.health_status == EnrollmentState.PENDING_APPROVAL]

    def _record_audit(
        self,
        admin_id: str,
        action: str,
        target_id: str,
        details: Dict[str, Any],
        admin_token: str = "",
    ) -> None:
        """Helper to append immutable audit entry into fleet_audit_log."""
        token_hash = hashlib.sha256(admin_token.encode()).hexdigest() if admin_token else "INTERNAL_ACTION"
        entry = AdminAuditEntry(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            admin_id=admin_id,
            action=action,
            target_type="ENDPOINT",
            target_id=target_id,
            timestamp=time.time(),
            details=details,
            auth_token_hash=token_hash,
        )
        self.db.record_audit_log(entry)

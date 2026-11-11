"""
BI Antivirus - Enterprise Fleet Manager
Core orchestrator for fleet registration, heartbeat monitoring, policy distribution,
incident management, device isolation, and administrator audit controls.
Targeting functional feature parity with Bitdefender GravityZone Business Security.
"""

import time
import uuid
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from bi_antivirus.enterprise.fleet_models import (
    EndpointDevice,
    FleetPolicy,
    FleetEvent,
    AdminAuditEntry,
    FleetIncident,
)
from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.config import (
    API_KEY_FILE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)

logger = logging.getLogger("BI_FleetManager")

# Default Enterprise Baseline Policy
DEFAULT_BASELINE_RULES = {
    "realtime_protection": True,
    "web_protection": True,
    "heuristic_analysis": True,
    "usb_sentinel": {
        "enabled": True,
        "block_unauthorized_usb": False,
        "require_pin_approval": True,
    },
    "ransomware_shield": {
        "enabled": True,
        "canary_decoy_monitoring": True,
        "mutation_burst_detection": True,
        "entropy_spike_threshold": 7.2,
    },
    "exploit_shield": {
        "audit_dep_aslr": True,
        "enforce_cfg": True,
    },
    "scheduled_scans": [
        {"type": "QUICK", "frequency": "daily", "time": "12:00"},
        {"type": "FULL", "frequency": "weekly", "day": "Sunday", "time": "02:00"},
    ],
    "edr_telemetry": {
        "enabled": True,
        "process_tree_tracking": True,
        "network_socket_tracking": True,
    },
    "firewall": {
        "block_inbound_smb": True,
        "block_suspicious_outbound_ports": [4444, 5555, 6666, 31337],
    },
}


class FleetManager:
    """Central orchestrator for enterprise endpoint fleet administration."""

    def __init__(
        self,
        fleet_db: Optional[FleetDatabase] = None,
        master_enrollment_key: Optional[str] = None,
        admin_token: Optional[str] = None,
    ):
        self.db = fleet_db or FleetDatabase()
        self.master_enrollment_key = master_enrollment_key or self._load_or_create_enrollment_key()
        self.admin_token = admin_token or self._load_or_create_admin_token()

        # Initialize Default Baseline Policy if none exists
        self._ensure_baseline_policy()

    def _load_or_create_enrollment_key(self) -> str:
        """Derive or load stable master enrollment key for agent authentication."""
        try:
            if API_KEY_FILE.exists():
                seed = API_KEY_FILE.read_text(encoding="utf-8").strip()
                return hashlib.sha256(f"BI_FLEET_ENROLL_{seed}".encode()).hexdigest()
        except Exception:
            pass
        return "BI-FLEET-MASTER-ENROLLMENT-KEY-2026"

    def _load_or_create_admin_token(self) -> str:
        """Derive or load stable admin management token."""
        try:
            if API_KEY_FILE.exists():
                seed = API_KEY_FILE.read_text(encoding="utf-8").strip()
                return hashlib.sha256(f"BI_FLEET_ADMIN_{seed}".encode()).hexdigest()
        except Exception:
            pass
        return "BI-FLEET-ADMIN-SECRET-TOKEN-SECURE"

    def _ensure_baseline_policy(self) -> None:
        """Ensure default baseline policy exists in fleet database."""
        existing = self.db.get_policy("POL-DEFAULT-V1")
        if not existing:
            baseline = FleetPolicy(
                policy_id="POL-DEFAULT-V1",
                policy_name="Enterprise Default Baseline Policy",
                version=1,
                rules=DEFAULT_BASELINE_RULES,
                description="Standard hardening policy featuring Real-Time Scan, Ransomware Shield, and Exploit Auditing.",
            )
            self.db.save_policy(baseline)

    # --- Authentication & Authorization ---

    def verify_admin_auth(self, token: str) -> bool:
        """Verify administrator bearer authorization token."""
        if not token:
            return False
        return hmac.compare_digest(token.strip(), self.admin_token)

    def verify_enrollment_token(self, token: str) -> bool:
        """Verify agent enrollment authorization token."""
        if not token:
            return False
        return hmac.compare_digest(token.strip(), self.master_enrollment_key)

    def _log_admin_action(
        self,
        admin_id: str,
        action: str,
        target_type: str,
        target_id: str,
        details: Dict[str, Any],
        token: str,
    ) -> None:
        """Record administrator operation in immutable audit log."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        entry = AdminAuditEntry(
            audit_id=f"AUD-{int(time.time())}-{uuid.uuid4().hex[:6]}",
            admin_id=admin_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            timestamp=time.time(),
            details=details,
            auth_token_hash=token_hash,
        )
        self.db.record_audit_log(entry)

    # --- Agent Lifecycle & Registration ---

    def register_endpoint(
        self,
        hostname: str,
        ip_address: str,
        os_version: str,
        agent_version: str,
        enrollment_token: str,
        endpoint_id: Optional[str] = None,
        department: str = "Corporate",
        tags: Optional[List[str]] = None,
        mac_address: str = "",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Securely register an endpoint into the fleet.
        Returns: (success, message, endpoint_data)
        """
        if not self.verify_enrollment_token(enrollment_token):
            logger.warning(f"Rejected endpoint registration for {hostname}: invalid enrollment token.")
            return False, "Enrollment token verification failed.", None

        ep_id = endpoint_id or f"EP-{uuid.uuid4().hex[:12].upper()}"
        endpoint = EndpointDevice(
            id=ep_id,
            hostname=hostname,
            ip_address=ip_address,
            os_version=os_version,
            agent_version=agent_version,
            last_seen=time.time(),
            health_status="HEALTHY",
            assigned_policy_id="POL-DEFAULT-V1",
            tags=tags or ["endpoint", department.lower()],
            isolation_status=False,
            department=department,
            mac_address=mac_address,
            registered_at=time.time(),
            enrollment_token=hashlib.sha256(enrollment_token.encode()).hexdigest()[:16],
        )

        ok = self.db.register_endpoint(endpoint)
        if ok:
            # Record registration event
            event = FleetEvent(
                event_id=f"EVT-{int(time.time())}-{uuid.uuid4().hex[:6]}",
                endpoint_id=ep_id,
                event_type="ENDPOINT_REGISTERED",
                severity="INFO",
                payload={
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "os_version": os_version,
                    "agent_version": agent_version,
                    "department": department,
                },
            )
            self.db.record_fleet_event(event)
            logger.info(f"Successfully registered endpoint: {hostname} ({ep_id})")
            return True, "Registration successful.", endpoint.to_dict()
        return False, "Database registration write failed.", None

    def process_heartbeat(
        self,
        endpoint_id: str,
        ip_address: Optional[str] = None,
        health_status: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Process agent heartbeat, update last_seen, and return active policy.
        """
        endpoint = self.db.get_endpoint(endpoint_id)
        if not endpoint:
            return False, "Endpoint not found in fleet directory.", None

        self.db.update_heartbeat(endpoint_id, ip_address=ip_address)
        if health_status and health_status in ("HEALTHY", "AT_RISK", "OFFLINE"):
            self.db.update_endpoint_health(endpoint_id, health_status)

        # Return assigned policy
        policy = self.db.get_policy(endpoint.assigned_policy_id) or self.db.get_policy("POL-DEFAULT-V1")
        return True, "Heartbeat acknowledged.", {
            "endpoint_id": endpoint_id,
            "isolation_status": endpoint.isolation_status,
            "assigned_policy": policy.to_dict() if policy else None,
        }

    def sweep_offline_endpoints(self, timeout_seconds: float = 300.0) -> int:
        """
        Scan all endpoints and mark any whose heartbeat is older than timeout as OFFLINE.
        Default timeout is 300 seconds (5 minutes).
        """
        now = time.time()
        endpoints = self.db.list_endpoints()
        offline_count = 0

        for ep in endpoints:
            if ep.health_status != "OFFLINE" and (now - ep.last_seen) > timeout_seconds:
                self.db.update_endpoint_health(ep.id, "OFFLINE")
                offline_count += 1
                logger.info(f"Endpoint {ep.hostname} ({ep.id}) marked OFFLINE (inactive for {int(now - ep.last_seen)}s)")

        return offline_count

    # --- Telemetry & Incident Aggregation ---

    def record_endpoint_event(
        self,
        endpoint_id: str,
        event_type: str,
        severity: str,
        payload: Dict[str, Any],
    ) -> bool:
        """
        Record endpoint telemetry event and evaluate for incident creation.
        """
        endpoint = self.db.get_endpoint(endpoint_id)
        if not endpoint:
            logger.warning(f"Event submitted for unknown endpoint: {endpoint_id}")
            return False

        event = FleetEvent(
            event_id=f"EVT-{int(time.time())}-{uuid.uuid4().hex[:6]}",
            endpoint_id=endpoint_id,
            event_type=event_type,
            severity=severity,
            payload=payload,
            timestamp=time.time(),
        )
        self.db.record_fleet_event(event)

        # Adjust endpoint health if severity is HIGH or CRITICAL
        if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            self.db.update_endpoint_health(endpoint_id, "AT_RISK")

        # Automatically create or aggregate into a FleetIncident if CRITICAL
        if severity == SEVERITY_CRITICAL:
            self._aggregate_incident_from_event(endpoint, event)

        return True

    def _aggregate_incident_from_event(self, endpoint: EndpointDevice, event: FleetEvent) -> None:
        """Correlate critical alert into new or existing incident."""
        threat_name = event.payload.get("threat_name", event.event_type)
        title = f"Critical Threat Alert: {threat_name} on {endpoint.hostname}"

        incident = FleetIncident(
            incident_id=f"INC-{int(time.time())}-{uuid.uuid4().hex[:6]}",
            severity=SEVERITY_CRITICAL,
            title=title,
            affected_endpoints=[endpoint.id],
            root_cause=f"High-severity detection ({event.event_type}): {threat_name}",
            status="ACTIVE",
            timeline=[
                {
                    "timestamp": time.time(),
                    "event": "Incident triggered by endpoint detection.",
                    "endpoint": endpoint.hostname,
                    "event_type": event.event_type,
                    "details": event.payload,
                }
            ],
            created_at=time.time(),
            updated_at=time.time(),
        )
        self.db.save_incident(incident)
        logger.info(f"Created enterprise incident {incident.incident_id}: {title}")

    # --- Policy Distribution & Rollback Protection ---

    def create_or_update_policy(
        self,
        admin_token: str,
        policy_id: str,
        policy_name: str,
        version: int,
        rules: Dict[str, Any],
        description: str = "",
        admin_id: str = "admin",
    ) -> Tuple[bool, str]:
        """
        Create or update a policy with monotonic version check to prevent rollback attacks.
        """
        if not self.verify_admin_auth(admin_token):
            return False, "Unauthorized: invalid administrator token."

        existing = self.db.get_policy(policy_id)
        if existing:
            # Monotonic sequence check: new version must be strictly greater
            if version <= existing.version:
                msg = f"Rollback rejected: new policy version ({version}) must be strictly greater than active version ({existing.version})."
                logger.warning(msg)
                return False, msg

        policy = FleetPolicy(
            policy_id=policy_id,
            policy_name=policy_name,
            version=version,
            rules=rules,
            created_at=existing.created_at if existing else time.time(),
            updated_at=time.time(),
            description=description,
        )

        ok = self.db.save_policy(policy)
        if ok:
            self._log_admin_action(
                admin_id=admin_id,
                action="POLICY_UPDATED" if existing else "POLICY_CREATED",
                target_type="POLICY",
                target_id=policy_id,
                details={"version": version, "name": policy_name},
                token=admin_token,
            )
            return True, f"Policy {policy_id} saved successfully at version {version}."
        return False, "Failed writing policy to fleet database."

    def assign_policy_to_endpoints(
        self,
        admin_token: str,
        policy_id: str,
        endpoint_ids: List[str],
        admin_id: str = "admin",
    ) -> Tuple[bool, str, int]:
        """Assign policy to specified endpoints."""
        if not self.verify_admin_auth(admin_token):
            return False, "Unauthorized: invalid administrator token.", 0

        policy = self.db.get_policy(policy_id)
        if not policy:
            return False, f"Policy {policy_id} does not exist.", 0

        success_count = 0
        for ep_id in endpoint_ids:
            if self.db.assign_policy_to_endpoint(ep_id, policy_id):
                success_count += 1

        self._log_admin_action(
            admin_id=admin_id,
            action="POLICY_ASSIGNED",
            target_type="POLICY",
            target_id=policy_id,
            details={"assigned_count": success_count, "targets": endpoint_ids},
            token=admin_token,
        )
        return True, f"Policy {policy_id} assigned to {success_count} endpoint(s).", success_count

    # --- Containment & Network Isolation ---

    def isolate_endpoint(
        self,
        admin_token: str,
        endpoint_id: str,
        admin_id: str = "admin",
        reason: str = "Containment of suspected compromise",
    ) -> Tuple[bool, str]:
        """Isolate an endpoint from network traffic for containment."""
        if not self.verify_admin_auth(admin_token):
            return False, "Unauthorized: invalid administrator token."

        ep = self.db.get_endpoint(endpoint_id)
        if not ep:
            return False, f"Endpoint {endpoint_id} not found."

        ok = self.db.update_endpoint_isolation(endpoint_id, isolated=True)
        if ok:
            self.db.update_endpoint_health(endpoint_id, "AT_RISK")
            self._log_admin_action(
                admin_id=admin_id,
                action="ENDPOINT_ISOLATED",
                target_type="ENDPOINT",
                target_id=endpoint_id,
                details={"reason": reason, "hostname": ep.hostname},
                token=admin_token,
            )
            logger.warning(f"Admin {admin_id} ISOLATED endpoint {ep.hostname} ({endpoint_id}): {reason}")
            return True, f"Endpoint {ep.hostname} isolated successfully."
        return False, "Failed updating isolation status in database."

    def unisolate_endpoint(
        self,
        admin_token: str,
        endpoint_id: str,
        admin_id: str = "admin",
    ) -> Tuple[bool, str]:
        """Restore network connectivity to a previously isolated endpoint."""
        if not self.verify_admin_auth(admin_token):
            return False, "Unauthorized: invalid administrator token."

        ep = self.db.get_endpoint(endpoint_id)
        if not ep:
            return False, f"Endpoint {endpoint_id} not found."

        ok = self.db.update_endpoint_isolation(endpoint_id, isolated=False)
        if ok:
            self._log_admin_action(
                admin_id=admin_id,
                action="ENDPOINT_UNISOLATED",
                target_type="ENDPOINT",
                target_id=endpoint_id,
                details={"hostname": ep.hostname},
                token=admin_token,
            )
            logger.info(f"Admin {admin_id} restored network connectivity for {ep.hostname} ({endpoint_id})")
            return True, f"Endpoint {ep.hostname} restored from isolation."
        return False, "Failed updating isolation status in database."

    # --- Search, Grouping & Inventory ---

    def search_endpoints(
        self,
        query: str = "",
        health_status: Optional[str] = None,
        department: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search and group endpoints by hostname, IP, tag, or department."""
        all_eps = self.db.list_endpoints(health_status=health_status, department=department, tag=tag)
        if not query:
            return [e.to_dict() for e in all_eps]

        q = query.lower().strip()
        matched = []
        for ep in all_eps:
            if (
                q in ep.hostname.lower()
                or q in ep.ip_address.lower()
                or q in ep.department.lower()
                or any(q in t.lower() for t in ep.tags)
                or q in ep.id.lower()
            ):
                matched.append(ep.to_dict())
        return matched

    def get_fleet_overview(self) -> Dict[str, Any]:
        """Return comprehensive overview of fleet health, statistics, and policies."""
        stats = self.db.get_fleet_stats()
        policies = self.db.list_policies()
        recent_incidents = self.db.list_incidents(status="ACTIVE")
        recent_events = self.db.get_fleet_events(limit=10)

        return {
            "statistics": stats,
            "policies": [p.to_dict() for p in policies],
            "active_incidents": [i.to_dict() for i in recent_incidents],
            "recent_events": [e.to_dict() for e in recent_events],
        }

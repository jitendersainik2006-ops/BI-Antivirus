"""
BI Antivirus - Enterprise Fleet Management Data Models
Defines dataclasses for endpoints, policies, events, audit logs, and incidents.
Targeting functional feature parity with Bitdefender GravityZone Business Security.
"""

import time
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


@dataclass
class EndpointDevice:
    """Represents a managed workstation or server endpoint in the enterprise fleet."""
    id: str
    hostname: str
    ip_address: str
    os_version: str
    agent_version: str
    last_seen: float = field(default_factory=time.time)
    health_status: str = "HEALTHY"  # HEALTHY, AT_RISK, OFFLINE
    assigned_policy_id: str = "POL-DEFAULT-V1"
    tags: List[str] = field(default_factory=list)
    isolation_status: bool = False  # True if network isolated for quarantine/containment
    department: str = "Corporate"
    mac_address: str = ""
    registered_at: float = field(default_factory=time.time)
    enrollment_token: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EndpointDevice":
        tags = data.get("tags", [])
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = [t.strip() for t in tags.split(",") if t.strip()]
        return cls(
            id=data["id"],
            hostname=data.get("hostname", "Unknown"),
            ip_address=data.get("ip_address", "127.0.0.1"),
            os_version=data.get("os_version", "Windows"),
            agent_version=data.get("agent_version", "1.0.0"),
            last_seen=float(data.get("last_seen", time.time())),
            health_status=data.get("health_status", "HEALTHY"),
            assigned_policy_id=data.get("assigned_policy_id", "POL-DEFAULT-V1"),
            tags=tags,
            isolation_status=bool(data.get("isolation_status", False)),
            department=data.get("department", "Corporate"),
            mac_address=data.get("mac_address", ""),
            registered_at=float(data.get("registered_at", time.time())),
            enrollment_token=data.get("enrollment_token", ""),
        )


@dataclass
class FleetPolicy:
    """Enterprise security policy applied across endpoints."""
    policy_id: str
    policy_name: str
    version: int
    rules: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FleetPolicy":
        rules = data.get("rules", {})
        if isinstance(rules, str):
            try:
                rules = json.loads(rules)
            except Exception:
                rules = {}
        return cls(
            policy_id=data["policy_id"],
            policy_name=data.get("policy_name", "Default Policy"),
            version=int(data.get("version", 1)),
            rules=rules,
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
            description=data.get("description", ""),
        )


@dataclass
class FleetEvent:
    """Security telemetry event emitted by an endpoint."""
    event_id: str
    endpoint_id: str
    event_type: str  # THREAT_DETECTED, QUARANTINE_ACTION, POLICY_APPLIED, HEARTBEAT, EXPLOIT_BLOCKED
    severity: str    # CRITICAL, HIGH, MEDIUM, LOW, INFO
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FleetEvent":
        payload = data.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        return cls(
            event_id=data["event_id"],
            endpoint_id=data["endpoint_id"],
            event_type=data.get("event_type", "INFO"),
            severity=data.get("severity", "INFO"),
            payload=payload,
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class AdminAuditEntry:
    """Immutable audit log record of administrator actions."""
    audit_id: str
    admin_id: str
    action: str
    target_type: str  # ENDPOINT, POLICY, INCIDENT, SYSTEM
    target_id: str
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)
    auth_token_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdminAuditEntry":
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        return cls(
            audit_id=data["audit_id"],
            admin_id=data.get("admin_id", "admin"),
            action=data.get("action", ""),
            target_type=data.get("target_type", "SYSTEM"),
            target_id=data.get("target_id", ""),
            timestamp=float(data.get("timestamp", time.time())),
            details=details,
            auth_token_hash=data.get("auth_token_hash", ""),
        )


@dataclass
class FleetIncident:
    """Aggregated security incident correlating one or more endpoint alerts."""
    incident_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    affected_endpoints: List[str]
    root_cause: str
    status: str = "ACTIVE"  # ACTIVE, INVESTIGATING, CONTAINED, RESOLVED
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FleetIncident":
        endpoints = data.get("affected_endpoints", [])
        if isinstance(endpoints, str):
            try:
                endpoints = json.loads(endpoints)
            except Exception:
                endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
        timeline = data.get("timeline", [])
        if isinstance(timeline, str):
            try:
                timeline = json.loads(timeline)
            except Exception:
                timeline = []
        return cls(
            incident_id=data["incident_id"],
            severity=data.get("severity", "MEDIUM"),
            title=data.get("title", "Untitled Incident"),
            affected_endpoints=endpoints,
            root_cause=data.get("root_cause", ""),
            status=data.get("status", "ACTIVE"),
            timeline=timeline,
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )


@dataclass
class CertificateRecord:
    """X.509 Certificate tracking record for local PKI and mTLS authentication."""
    serial_number: str
    endpoint_id: str
    common_name: str
    certificate_type: str  # CA, SERVER, CLIENT
    status: str = "ACTIVE"  # PENDING_APPROVAL, APPROVED, ACTIVE, REVOKED, EXPIRED
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=time.time)
    revoked_at: Optional[float] = None
    revocation_reason: str = ""
    cert_path: str = ""
    fingerprint_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CertificateRecord":
        return cls(
            serial_number=str(data["serial_number"]),
            endpoint_id=data.get("endpoint_id", ""),
            common_name=data.get("common_name", ""),
            certificate_type=data.get("certificate_type", "CLIENT"),
            status=data.get("status", "ACTIVE"),
            issued_at=float(data.get("issued_at", time.time())),
            expires_at=float(data.get("expires_at", time.time())),
            revoked_at=float(data["revoked_at"]) if data.get("revoked_at") is not None else None,
            revocation_reason=data.get("revocation_reason", ""),
            cert_path=data.get("cert_path", ""),
            fingerprint_sha256=data.get("fingerprint_sha256", ""),
        )


@dataclass
class PolicyReceipt:
    """Cryptographic acknowledgement and audit record of policy application."""
    receipt_id: str
    endpoint_id: str
    policy_id: str
    version: int
    status: str  # APPLIED, REJECTED, ROLLED_BACK
    applied_at: float = field(default_factory=time.time)
    hmac_signature: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyReceipt":
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        return cls(
            receipt_id=data["receipt_id"],
            endpoint_id=data["endpoint_id"],
            policy_id=data["policy_id"],
            version=int(data.get("version", 1)),
            status=data.get("status", "APPLIED"),
            applied_at=float(data.get("applied_at", time.time())),
            hmac_signature=data.get("hmac_signature", ""),
            details=details,
        )


@dataclass
class SandboxAuditRecord:
    """Execution telemetry record for isolated sandbox verification."""
    audit_id: str
    sample_name: str
    sample_sha256: str
    hyperv_available: bool
    isolation_mode: str  # HYPERV_ISOLATED, LOCAL_CONTAINMENT_SIM
    duration_seconds: float
    exit_code: int
    verdict: str  # BENIGN, SUSPICIOUS, MALICIOUS, TIMEOUT, ABORTED
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SandboxAuditRecord":
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        return cls(
            audit_id=data["audit_id"],
            sample_name=data.get("sample_name", "unknown"),
            sample_sha256=data.get("sample_sha256", ""),
            hyperv_available=bool(data.get("hyperv_available", False)),
            isolation_mode=data.get("isolation_mode", "LOCAL_CONTAINMENT_SIM"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            exit_code=int(data.get("exit_code", 0)),
            verdict=data.get("verdict", "BENIGN"),
            timestamp=float(data.get("timestamp", time.time())),
            details=details,
        )


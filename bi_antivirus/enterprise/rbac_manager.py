"""
BI Antivirus - Role-Based Access Control (RBAC) Manager
Provides enterprise multi-tier role authorization, granular permission mapping,
session token tracking, and administrative access gating.

Supported Roles:
- SUPER_ADMIN: Full system control, policy editing, host isolation, firewall rules, and role management.
- SEC_OPS: Threat response, incident triage, host isolation, quarantine actions, and rule staging.
- AUDITOR: Read-only compliance inspection, SIEM log export, telemetry review, and hash-chain verification.
- READ_ONLY: Basic operational status viewing and local scan history review.
"""

import time
import uuid
import hmac
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger("BI_RBACManager")

# Standard Permissions
PERM_VIEW_DASHBOARD = "VIEW_DASHBOARD"
PERM_RUN_SCAN = "RUN_SCAN"
PERM_MANAGE_QUARANTINE = "MANAGE_QUARANTINE"
PERM_ISOLATE_HOST = "ISOLATE_HOST"
PERM_TERMINATE_PROCESS = "TERMINATE_PROCESS"
PERM_MANAGE_FIREWALL = "MANAGE_FIREWALL"
PERM_EDIT_POLICIES = "EDIT_POLICIES"
PERM_EXPORT_AUDIT_LOGS = "EXPORT_AUDIT_LOGS"
PERM_MANAGE_RBAC = "MANAGE_RBAC"
PERM_ROLLBACK_RULES = "ROLLBACK_RULES"

# Role to Permissions Matrix
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "SUPER_ADMIN": {
        PERM_VIEW_DASHBOARD,
        PERM_RUN_SCAN,
        PERM_MANAGE_QUARANTINE,
        PERM_ISOLATE_HOST,
        PERM_TERMINATE_PROCESS,
        PERM_MANAGE_FIREWALL,
        PERM_EDIT_POLICIES,
        PERM_EXPORT_AUDIT_LOGS,
        PERM_MANAGE_RBAC,
        PERM_ROLLBACK_RULES,
    },
    "SEC_OPS": {
        PERM_VIEW_DASHBOARD,
        PERM_RUN_SCAN,
        PERM_MANAGE_QUARANTINE,
        PERM_ISOLATE_HOST,
        PERM_TERMINATE_PROCESS,
        PERM_MANAGE_FIREWALL,
        PERM_EXPORT_AUDIT_LOGS,
    },
    "AUDITOR": {
        PERM_VIEW_DASHBOARD,
        PERM_EXPORT_AUDIT_LOGS,
    },
    "READ_ONLY": {
        PERM_VIEW_DASHBOARD,
    },
}


@dataclass
class UserAccount:
    """Enterprise user credential and role record."""
    username: str
    role: str
    password_hash: str
    created_at: float = field(default_factory=time.time)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


@dataclass
class UserSession:
    """Active session token record."""
    session_id: str
    username: str
    role: str
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 28800.0)  # 8 hours


class RBACManager:
    """Manages role-based access control, session validation, and permissions."""

    def __init__(self, signing_secret: Optional[bytes] = None):
        self.signing_secret = signing_secret or b"BI_ENTERPRISE_RBAC_SESSION_SECRET_2026"
        self._users: Dict[str, UserAccount] = {}
        self._sessions: Dict[str, UserSession] = {}

        # Initialize default administrative accounts
        self._init_default_accounts()

    def _hash_password(self, password: str) -> str:
        """Secure PBKDF2 password hash."""
        salt = b"BI_SALT_ENTERPRISE_2026"
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000).hex()

    def _init_default_accounts(self) -> None:
        """Create bootstrap accounts for standard roles."""
        self.create_user("admin", "SUPER_ADMIN", "Admin@Secure2026!")
        self.create_user("secops", "SEC_OPS", "SecOps@2026!")
        self.create_user("auditor", "AUDITOR", "Auditor@2026!")
        self.create_user("guest", "READ_ONLY", "GuestReadOnly123!")

    def create_user(self, username: str, role: str, password: str) -> bool:
        """Create or update a user account with assigned role."""
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Invalid role: {role}. Must be one of {list(ROLE_PERMISSIONS.keys())}")

        uname = username.lower().strip()
        self._users[uname] = UserAccount(
            username=uname,
            role=role,
            password_hash=self._hash_password(password),
        )
        return True

    def authenticate(self, username: str, password: str) -> Optional[UserSession]:
        """Authenticate user credentials and issue session token."""
        uname = username.lower().strip()
        user = self._users.get(uname)
        if not user or not user.is_active:
            return None

        expected_hash = self._hash_password(password)
        if not hmac.compare_digest(user.password_hash, expected_hash):
            return None

        # Issue secure session token
        session_id = f"BI-SESS-{uuid.uuid4().hex}"
        session = UserSession(session_id=session_id, username=uname, role=user.role)
        self._sessions[session_id] = session
        return session

    def validate_session(self, session_token: str) -> Optional[UserSession]:
        """Validate session token and verify expiration."""
        sess = self._sessions.get(session_token)
        if not sess:
            return None

        if time.time() > sess.expires_at:
            del self._sessions[session_token]
            return None

        return sess

    def has_permission(self, role: str, permission: str) -> bool:
        """Check if role holds specified permission."""
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms

    def authorize_action(self, role_or_session: str, permission: str) -> Tuple[bool, str]:
        """
        Authorize action by either direct role name or active session token.
        Returns: (is_authorized, reason)
        """
        # Check if argument is a session token
        if role_or_session in self._sessions:
            sess = self.validate_session(role_or_session)
            if not sess:
                return False, "Session has expired or is invalid."
            role = sess.role
        else:
            role = role_or_session

        if self.has_permission(role, permission):
            return True, f"Authorized: Role '{role}' has permission '{permission}'."
        else:
            return False, f"Permission Denied: Role '{role}' lacks required permission '{permission}'."

    def list_users(self) -> List[Dict[str, Any]]:
        """List all registered users without exposing password hashes."""
        return [u.to_dict() for u in self._users.values()]

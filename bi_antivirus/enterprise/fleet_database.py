"""
BI Antivirus - Enterprise Fleet Database
Thread-safe SQLite storage for endpoints, fleet policies, events, incidents, and audit logs.
Targeting functional feature parity with Bitdefender GravityZone Business Security.
"""

import sqlite3
import threading
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from bi_antivirus.config import FLEET_DB_PATH
from bi_antivirus.enterprise.fleet_models import (
    EndpointDevice,
    FleetPolicy,
    FleetEvent,
    AdminAuditEntry,
    FleetIncident,
)

logger = logging.getLogger("BI_FleetDatabase")


class FleetDatabase:
    """Thread-safe SQLite database manager for enterprise fleet security."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or FLEET_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _init_database(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # 1. Fleet Endpoints
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fleet_endpoints (
                        id TEXT PRIMARY KEY,
                        hostname TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        os_version TEXT NOT NULL,
                        agent_version TEXT NOT NULL,
                        last_seen REAL NOT NULL,
                        health_status TEXT NOT NULL,
                        assigned_policy_id TEXT NOT NULL,
                        tags TEXT NOT NULL,
                        isolation_status INTEGER NOT NULL DEFAULT 0,
                        department TEXT NOT NULL DEFAULT 'Corporate',
                        mac_address TEXT NOT NULL DEFAULT '',
                        registered_at REAL NOT NULL,
                        enrollment_token TEXT NOT NULL DEFAULT ''
                    )
                """)

                # 2. Fleet Policies
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fleet_policies (
                        policy_id TEXT PRIMARY KEY,
                        policy_name TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        rules TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        description TEXT NOT NULL DEFAULT ''
                    )
                """)

                # 3. Fleet Events
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fleet_events (
                        event_id TEXT PRIMARY KEY,
                        endpoint_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                """)

                # 4. Fleet Incidents
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fleet_incidents (
                        incident_id TEXT PRIMARY KEY,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        affected_endpoints TEXT NOT NULL,
                        root_cause TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        timeline TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                """)

                # 5. Admin Audit Log (Immutable append-only record)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fleet_audit_log (
                        audit_id TEXT PRIMARY KEY,
                        admin_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target_type TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        details TEXT NOT NULL,
                        auth_token_hash TEXT NOT NULL DEFAULT ''
                    )
                """)

                # Indices
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_health ON fleet_endpoints(health_status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_dept ON fleet_endpoints(department)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_endpoint ON fleet_events(endpoint_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON fleet_events(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON fleet_incidents(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON fleet_audit_log(timestamp)")
                conn.commit()

    # --- Endpoints Management ---

    def register_endpoint(self, endpoint: EndpointDevice) -> bool:
        """Register or update an endpoint device."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO fleet_endpoints (
                            id, hostname, ip_address, os_version, agent_version,
                            last_seen, health_status, assigned_policy_id, tags,
                            isolation_status, department, mac_address, registered_at, enrollment_token
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            hostname = excluded.hostname,
                            ip_address = excluded.ip_address,
                            os_version = excluded.os_version,
                            agent_version = excluded.agent_version,
                            last_seen = excluded.last_seen,
                            health_status = excluded.health_status,
                            assigned_policy_id = excluded.assigned_policy_id,
                            tags = excluded.tags,
                            isolation_status = excluded.isolation_status,
                            department = excluded.department,
                            mac_address = excluded.mac_address
                    """, (
                        endpoint.id,
                        endpoint.hostname,
                        endpoint.ip_address,
                        endpoint.os_version,
                        endpoint.agent_version,
                        endpoint.last_seen,
                        endpoint.health_status,
                        endpoint.assigned_policy_id,
                        json.dumps(endpoint.tags),
                        1 if endpoint.isolation_status else 0,
                        endpoint.department,
                        endpoint.mac_address,
                        endpoint.registered_at,
                        endpoint.enrollment_token,
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed registering endpoint {endpoint.id}: {e}")
                return False

    def get_endpoint(self, endpoint_id: str) -> Optional[EndpointDevice]:
        """Fetch endpoint device by ID."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM fleet_endpoints WHERE id = ?", (endpoint_id,))
                    row = cursor.fetchone()
                    if row:
                        return EndpointDevice.from_dict(dict(row))
                    return None
            except Exception as e:
                logger.error(f"Failed fetching endpoint {endpoint_id}: {e}")
                return None

    def update_heartbeat(self, endpoint_id: str, ip_address: Optional[str] = None) -> bool:
        """Update last_seen timestamp and optionally IP for endpoint."""
        import time
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    now = time.time()
                    if ip_address:
                        cursor.execute("""
                            UPDATE fleet_endpoints
                            SET last_seen = ?, ip_address = ?, health_status = CASE WHEN health_status = 'OFFLINE' THEN 'HEALTHY' ELSE health_status END
                            WHERE id = ?
                        """, (now, ip_address, endpoint_id))
                    else:
                        cursor.execute("""
                            UPDATE fleet_endpoints
                            SET last_seen = ?, health_status = CASE WHEN health_status = 'OFFLINE' THEN 'HEALTHY' ELSE health_status END
                            WHERE id = ?
                        """, (now, endpoint_id))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed updating heartbeat for {endpoint_id}: {e}")
                return False

    def update_endpoint_health(self, endpoint_id: str, health_status: str) -> bool:
        """Update health status of endpoint (HEALTHY, AT_RISK, OFFLINE)."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE fleet_endpoints SET health_status = ? WHERE id = ?", (health_status, endpoint_id))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed updating health status for {endpoint_id}: {e}")
                return False

    def update_endpoint_isolation(self, endpoint_id: str, isolated: bool) -> bool:
        """Set network isolation flag on endpoint."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE fleet_endpoints SET isolation_status = ? WHERE id = ?", (1 if isolated else 0, endpoint_id))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed setting isolation for {endpoint_id}: {e}")
                return False

    def assign_policy_to_endpoint(self, endpoint_id: str, policy_id: str) -> bool:
        """Assign policy ID to an endpoint."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE fleet_endpoints SET assigned_policy_id = ? WHERE id = ?", (policy_id, endpoint_id))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed assigning policy {policy_id} to {endpoint_id}: {e}")
                return False

    def list_endpoints(
        self,
        health_status: Optional[str] = None,
        department: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[EndpointDevice]:
        """List endpoints matching optional filters."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    query = "SELECT * FROM fleet_endpoints WHERE 1=1"
                    params: List[Any] = []

                    if health_status:
                        query += " AND health_status = ?"
                        params.append(health_status)
                    if department:
                        query += " AND department = ?"
                        params.append(department)

                    cursor.execute(query + " ORDER BY hostname ASC", params)
                    rows = cursor.fetchall()
                    endpoints = [EndpointDevice.from_dict(dict(r)) for r in rows]

                    if tag:
                        tag_lower = tag.lower()
                        endpoints = [e for e in endpoints if any(tag_lower == t.lower() for t in e.tags)]

                    return endpoints
            except Exception as e:
                logger.error(f"Failed listing endpoints: {e}")
                return []

    def delete_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint record."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM fleet_endpoints WHERE id = ?", (endpoint_id,))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed deleting endpoint {endpoint_id}: {e}")
                return False

    # --- Policies Management ---

    def save_policy(self, policy: FleetPolicy) -> bool:
        """Insert or update a fleet policy."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO fleet_policies (
                            policy_id, policy_name, version, rules, created_at, updated_at, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(policy_id) DO UPDATE SET
                            policy_name = excluded.policy_name,
                            version = excluded.version,
                            rules = excluded.rules,
                            updated_at = excluded.updated_at,
                            description = excluded.description
                    """, (
                        policy.policy_id,
                        policy.policy_name,
                        policy.version,
                        json.dumps(policy.rules),
                        policy.created_at,
                        policy.updated_at,
                        policy.description,
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed saving policy {policy.policy_id}: {e}")
                return False

    def get_policy(self, policy_id: str) -> Optional[FleetPolicy]:
        """Fetch policy by ID."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM fleet_policies WHERE policy_id = ?", (policy_id,))
                    row = cursor.fetchone()
                    if row:
                        return FleetPolicy.from_dict(dict(row))
                    return None
            except Exception as e:
                logger.error(f"Failed fetching policy {policy_id}: {e}")
                return None

    def list_policies(self) -> List[FleetPolicy]:
        """List all fleet policies."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM fleet_policies ORDER BY policy_name ASC")
                    return [FleetPolicy.from_dict(dict(r)) for r in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Failed listing policies: {e}")
                return []

    # --- Events Management ---

    def record_fleet_event(self, event: FleetEvent) -> bool:
        """Record telemetry event from an endpoint."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO fleet_events (
                            event_id, endpoint_id, event_type, severity, payload, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.endpoint_id,
                        event.event_type,
                        event.severity,
                        json.dumps(event.payload),
                        event.timestamp,
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed recording event {event.event_id}: {e}")
                return False

    def get_fleet_events(
        self,
        endpoint_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[FleetEvent]:
        """Fetch recent fleet events with optional filtering."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    query = "SELECT * FROM fleet_events WHERE 1=1"
                    params: List[Any] = []

                    if endpoint_id:
                        query += " AND endpoint_id = ?"
                        params.append(endpoint_id)
                    if severity:
                        query += " AND severity = ?"
                        params.append(severity)

                    query += " ORDER BY timestamp DESC LIMIT ?"
                    params.append(limit)

                    cursor.execute(query, params)
                    return [FleetEvent.from_dict(dict(r)) for r in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Failed fetching fleet events: {e}")
                return []

    # --- Incidents Management ---

    def save_incident(self, incident: FleetIncident) -> bool:
        """Insert or update a fleet incident."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO fleet_incidents (
                            incident_id, severity, title, affected_endpoints, root_cause,
                            status, timeline, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(incident_id) DO UPDATE SET
                            severity = excluded.severity,
                            title = excluded.title,
                            affected_endpoints = excluded.affected_endpoints,
                            root_cause = excluded.root_cause,
                            status = excluded.status,
                            timeline = excluded.timeline,
                            updated_at = excluded.updated_at
                    """, (
                        incident.incident_id,
                        incident.severity,
                        incident.title,
                        json.dumps(incident.affected_endpoints),
                        incident.root_cause,
                        incident.status,
                        json.dumps(incident.timeline),
                        incident.created_at,
                        incident.updated_at,
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed saving incident {incident.incident_id}: {e}")
                return False

    def get_incident(self, incident_id: str) -> Optional[FleetIncident]:
        """Fetch incident by ID."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM fleet_incidents WHERE incident_id = ?", (incident_id,))
                    row = cursor.fetchone()
                    if row:
                        return FleetIncident.from_dict(dict(row))
                    return None
            except Exception as e:
                logger.error(f"Failed fetching incident {incident_id}: {e}")
                return None

    def list_incidents(self, status: Optional[str] = None) -> List[FleetIncident]:
        """List fleet incidents."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    if status:
                        cursor.execute("SELECT * FROM fleet_incidents WHERE status = ? ORDER BY created_at DESC", (status,))
                    else:
                        cursor.execute("SELECT * FROM fleet_incidents ORDER BY created_at DESC")
                    return [FleetIncident.from_dict(dict(r)) for r in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Failed listing incidents: {e}")
                return []

    # --- Audit Log Management ---

    def record_audit_log(self, entry: AdminAuditEntry) -> bool:
        """Append an entry to the immutable administrator audit log."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO fleet_audit_log (
                            audit_id, admin_id, action, target_type, target_id,
                            timestamp, details, auth_token_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry.audit_id,
                        entry.admin_id,
                        entry.action,
                        entry.target_type,
                        entry.target_id,
                        entry.timestamp,
                        json.dumps(entry.details),
                        entry.auth_token_hash,
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed recording audit log: {e}")
                return False

    def get_audit_log(self, limit: int = 100) -> List[AdminAuditEntry]:
        """Retrieve recent administrator audit entries."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM fleet_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
                    return [AdminAuditEntry.from_dict(dict(r)) for r in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Failed fetching audit log: {e}")
                return []

    # --- Aggregate Statistics ---

    def get_fleet_stats(self) -> Dict[str, Any]:
        """Compute aggregate fleet telemetry and posture statistics."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()

                    cursor.execute("SELECT COUNT(*) FROM fleet_endpoints")
                    total_endpoints = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_endpoints WHERE health_status = 'HEALTHY'")
                    healthy = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_endpoints WHERE health_status = 'AT_RISK'")
                    at_risk = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_endpoints WHERE health_status = 'OFFLINE'")
                    offline = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_endpoints WHERE isolation_status = 1")
                    isolated = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_incidents WHERE status IN ('ACTIVE', 'INVESTIGATING')")
                    active_incidents = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM fleet_events")
                    total_events = cursor.fetchone()[0]

                    return {
                        "total_endpoints": total_endpoints,
                        "healthy_count": healthy,
                        "at_risk_count": at_risk,
                        "offline_count": offline,
                        "isolated_count": isolated,
                        "active_incidents": active_incidents,
                        "total_events": total_events,
                    }
            except Exception as e:
                logger.error(f"Failed compiling fleet stats: {e}")
                return {
                    "total_endpoints": 0,
                    "healthy_count": 0,
                    "at_risk_count": 0,
                    "offline_count": 0,
                    "isolated_count": 0,
                    "active_incidents": 0,
                    "total_events": 0,
                }

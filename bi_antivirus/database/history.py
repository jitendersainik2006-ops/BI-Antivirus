"""
BI Antivirus - Scan History and Threat Records Database
Manages historical scan sessions, threat detection logs, and audit logs
using SQLite database located on D: drive.
"""

import sqlite3
import json
from typing import Optional, List, Dict, Any
from pathlib import Path
from bi_antivirus.config import HISTORY_DB_PATH

class HistoryDatabase:
    """Stores scan session history and persistent threat event records."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or HISTORY_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables for scan sessions and threat detections."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    session_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target_path TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP,
                    duration_seconds REAL DEFAULT 0,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'COMPLETED'
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER DEFAULT 0,
                    threat_name TEXT NOT NULL,
                    threat_family TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action_taken TEXT DEFAULT 'FLAGGED',
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS edr_incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    root_entity TEXT,
                    mitre_techniques TEXT,
                    timeline_json TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    dep_status TEXT,
                    aslr_status TEXT,
                    cfg_status TEXT,
                    dynamic_code_status TEXT,
                    rwx_regions_count INTEGER DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    findings TEXT,
                    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS software_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    display_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    publisher TEXT,
                    install_date TEXT,
                    install_location TEXT,
                    vulnerability_status TEXT DEFAULT 'UNKNOWN',
                    matched_cve TEXT,
                    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_advisories (
                    cve_id TEXT PRIMARY KEY,
                    product_name TEXT NOT NULL,
                    vendor TEXT,
                    affected_versions_min TEXT,
                    affected_versions_max TEXT,
                    fixed_version TEXT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    published_date TEXT,
                    verified INTEGER DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pe_analysis_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    classification TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    confidence REAL DEFAULT 0.5,
                    is_pe64 INTEGER DEFAULT 1,
                    sections_count INTEGER DEFAULT 0,
                    suspicious_imports_count INTEGER DEFAULT 0,
                    findings_json TEXT,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_manifest (
                    feed_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    signatures_count INTEGER DEFAULT 0,
                    advisories_count INTEGER DEFAULT 0,
                    publisher TEXT,
                    signature_valid INTEGER DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def record_scan_session(
        self,
        session_id: str,
        scan_type: str,
        target_path: str,
        files_scanned: int,
        threats_found: int,
        duration_seconds: float,
        status: str = "COMPLETED",
    ) -> None:
        """Record completed scan session details."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scan_sessions (
                    session_id, scan_type, target_path, files_scanned, threats_found, duration_seconds, status, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (session_id, scan_type, target_path, files_scanned, threats_found, duration_seconds, status))
            conn.commit()

    def record_threat(
        self,
        session_id: Optional[str],
        file_path: str,
        file_hash: str,
        file_size: int,
        threat_name: str,
        threat_family: str,
        severity: str,
        action_taken: str = "FLAGGED",
        details: str = "",
    ) -> int:
        """Record an individual detected threat."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_detections (
                    session_id, file_path, file_hash, file_size, threat_name, threat_family, severity, action_taken, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, file_path, file_hash, file_size, threat_name, threat_family, severity, action_taken, details))
            conn.commit()
            return cursor.lastrowid

    def update_threat_action(self, threat_id: int, action: str) -> None:
        """Update action taken for a specific threat (e.g. QUARANTINED, RESTORED, IGNORED)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE threat_detections SET action_taken = ? WHERE id = ?", (action, threat_id))
            conn.commit()

    def get_recent_scans(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve recent scan sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id, scan_type, target_path, started_at, finished_at, duration_seconds, files_scanned, threats_found, status
                FROM scan_sessions
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_threat_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve historical threat detections."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, session_id, file_path, file_hash, file_size, threat_name, threat_family, severity, action_taken, detected_at, details
                FROM threat_detections
                ORDER BY detected_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Return total files scanned, total threats identified, and scan counts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), COALESCE(SUM(files_scanned), 0), COALESCE(SUM(threats_found), 0) FROM scan_sessions")
            scans_count, total_files, total_threats = cursor.fetchone()

            cursor.execute("SELECT COUNT(*) FROM threat_detections WHERE action_taken = 'QUARANTINED'")
            quarantined_count = cursor.fetchone()[0]

            cursor.execute("SELECT finished_at FROM scan_sessions ORDER BY finished_at DESC LIMIT 1")
            row = cursor.fetchone()
            last_scan_time = row[0] if row else "Never"

            return {
                "total_scans_performed": scans_count,
                "total_files_scanned": total_files,
                "total_threats_found": total_threats,
                "threats_quarantined": quarantined_count,
                "last_scan_time": last_scan_time,
            }

    def record_event(
        self,
        event_type: str,
        source: str,
        severity: str,
        details: str = "",
    ) -> int:
        """Record a general security event (e.g. Device Control, App Control, Baseline Alert)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_events (event_type, severity, source, message)
                VALUES (?, ?, ?, ?)
            """, (event_type, severity, source, details))
            conn.commit()
            return cursor.lastrowid

    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security audit events."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, event_type, severity, source, message, timestamp
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def record_edr_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        confidence: float,
        root_entity: str,
        mitre_techniques: Any,
        timeline: Any,
        status: str = "ACTIVE",
    ) -> None:
        """Record or update a correlated EDR incident."""
        techniques_str = json.dumps(mitre_techniques) if not isinstance(mitre_techniques, str) else mitre_techniques
        timeline_str = json.dumps(timeline) if not isinstance(timeline, str) else timeline

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO edr_incidents (
                    incident_id, title, severity, confidence, root_entity, mitre_techniques, timeline_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (incident_id, title, severity, confidence, root_entity, techniques_str, timeline_str, status))
            conn.commit()

    def get_edr_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve recent correlated EDR incidents with parsed JSON fields."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT incident_id, title, severity, confidence, root_entity, mitre_techniques, timeline_json, status, created_at
                FROM edr_incidents
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                try:
                    item["mitre_techniques"] = json.loads(item["mitre_techniques"]) if item.get("mitre_techniques") else []
                except Exception:
                    pass
                try:
                    item["timeline"] = json.loads(item["timeline_json"]) if item.get("timeline_json") else []
                except Exception:
                    item["timeline"] = []
                results.append(item)
            return results

    def get_edr_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific EDR incident by its unique ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT incident_id, title, severity, confidence, root_entity, mitre_techniques, timeline_json, status, created_at
                FROM edr_incidents
                WHERE incident_id = ?
            """, (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["mitre_techniques"] = json.loads(item["mitre_techniques"]) if item.get("mitre_techniques") else []
            except Exception:
                pass
            try:
                item["timeline"] = json.loads(item["timeline_json"]) if item.get("timeline_json") else []
            except Exception:
                item["timeline"] = []
            return item

    def record_memory_audit(
        self,
        pid: int,
        process_name: str,
        dep_status: str,
        aslr_status: str,
        cfg_status: str,
        dynamic_code_status: str = "UNKNOWN",
        rwx_regions_count: int = 0,
        risk_score: int = 0,
        findings: Any = "",
    ) -> int:
        """Record a defensive process memory posture audit."""
        findings_str = json.dumps(findings) if isinstance(findings, (list, dict)) else str(findings)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO memory_audit_events (
                    pid, process_name, dep_status, aslr_status, cfg_status, dynamic_code_status,
                    rwx_regions_count, risk_score, findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (pid, process_name, dep_status, aslr_status, cfg_status, dynamic_code_status,
                  rwx_regions_count, risk_score, findings_str))
            conn.commit()
            return cursor.lastrowid

    def get_recent_memory_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent process memory audits."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, pid, process_name, dep_status, aslr_status, cfg_status, dynamic_code_status,
                       rwx_regions_count, risk_score, findings, audited_at
                FROM memory_audit_events
                ORDER BY audited_at DESC
                LIMIT ?
            """, (limit,))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                try:
                    item["findings"] = json.loads(item["findings"]) if item.get("findings") else []
                except Exception:
                    pass
                results.append(item)
            return results

    def get_high_risk_memory_audits(self, min_risk_score: int = 40, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve memory audits with risk score meeting or exceeding threshold."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, pid, process_name, dep_status, aslr_status, cfg_status, dynamic_code_status,
                       rwx_regions_count, risk_score, findings, audited_at
                FROM memory_audit_events
                WHERE risk_score >= ?
                ORDER BY audited_at DESC
                LIMIT ?
            """, (min_risk_score, limit))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                try:
                    item["findings"] = json.loads(item["findings"]) if item.get("findings") else []
                except Exception:
                    pass
                results.append(item)
            return results

    def record_software_inventory(self, apps: List[Dict[str, Any]]) -> None:
        """Replace or update installed software inventory records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Clear previous audit snapshot
            cursor.execute("DELETE FROM software_inventory")
            for a in apps:
                cursor.execute("""
                    INSERT INTO software_inventory (
                        display_name, version, publisher, install_date, install_location,
                        vulnerability_status, matched_cve
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    a.get("display_name") or a.get("app_name", "Unknown"),
                    a.get("version", "0.0.0"),
                    a.get("publisher", "Unknown"),
                    a.get("install_date", ""),
                    a.get("install_location", ""),
                    a.get("vulnerability_status") or a.get("status", "UNKNOWN"),
                    a.get("matched_cve", ""),
                ))
            conn.commit()

    def get_software_inventory(self, limit: int = 200, filter_status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve installed software inventory, optionally filtered by status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if filter_status:
                cursor.execute("""
                    SELECT id, display_name, version, publisher, install_date, install_location,
                           vulnerability_status, matched_cve, audited_at
                    FROM software_inventory
                    WHERE vulnerability_status = ?
                    ORDER BY display_name ASC
                    LIMIT ?
                """, (filter_status, limit))
            else:
                cursor.execute("""
                    SELECT id, display_name, version, publisher, install_date, install_location,
                           vulnerability_status, matched_cve, audited_at
                    FROM software_inventory
                    ORDER BY display_name ASC
                    LIMIT ?
                """, (limit,))
            rows = []
            for row in cursor.fetchall():
                d = dict(row)
                d["app_name"] = d.get("display_name", "")
                d["status"] = d.get("vulnerability_status", "")
                rows.append(d)
            return rows

    def record_cve_advisory(
        self,
        cve_id: str,
        product_name: str,
        vendor: str,
        affected_versions_min: str,
        affected_versions_max: str,
        fixed_version: str,
        severity: str,
        title: str,
        description: str,
        published_date: str = "",
        verified: int = 1,
    ) -> None:
        """Record or update a local CVE vulnerability advisory."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cve_advisories (
                    cve_id, product_name, vendor, affected_versions_min, affected_versions_max,
                    fixed_version, severity, title, description, published_date, verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, product_name, vendor, affected_versions_min, affected_versions_max,
                  fixed_version, severity, title, description, published_date, verified))
            conn.commit()

    def get_cve_advisories(self, product_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve local vulnerability advisories, optionally filtered by product name."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if product_name:
                cursor.execute("""
                    SELECT cve_id, product_name, vendor, affected_versions_min, affected_versions_max,
                           fixed_version, severity, title, description, published_date, verified
                    FROM cve_advisories
                    WHERE product_name LIKE ?
                    ORDER BY cve_id DESC
                """, (f"%{product_name}%",))
            else:
                cursor.execute("""
                    SELECT cve_id, product_name, vendor, affected_versions_min, affected_versions_max,
                           fixed_version, severity, title, description, published_date, verified
                    FROM cve_advisories
                    ORDER BY cve_id DESC
                """)
            return [dict(row) for row in cursor.fetchall()]

    def record_pe_analysis(
        self,
        file_path: str,
        file_hash: str,
        classification: str,
        risk_score: int,
        confidence: float,
        is_pe64: int,
        sections_count: int,
        suspicious_imports_count: int,
        findings: Any = "",
    ) -> int:
        """Record static PE security classification analysis result."""
        findings_str = json.dumps(findings) if isinstance(findings, (list, dict)) else str(findings)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pe_analysis_records (
                    file_path, file_hash, classification, risk_score, confidence,
                    is_pe64, sections_count, suspicious_imports_count, findings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (file_path, file_hash, classification, risk_score, confidence,
                  is_pe64, sections_count, suspicious_imports_count, findings_str))
            conn.commit()
            return cursor.lastrowid

    def get_recent_pe_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent static PE inspection records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, file_path, file_hash, classification, risk_score, confidence,
                       is_pe64, sections_count, suspicious_imports_count, findings_json, analyzed_at
                FROM pe_analysis_records
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, (limit,))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                item["sha256"] = item.get("file_hash", "")
                try:
                    item["findings"] = json.loads(item["findings_json"]) if item.get("findings_json") else []
                except Exception:
                    item["findings"] = []
                results.append(item)
            return results

    def record_threat_intel_update(
        self,
        feed_id: str,
        version: str,
        sequence: int,
        signatures_count: int,
        advisories_count: int,
        publisher: str,
        signature_valid: int = 1,
    ) -> None:
        """Record verified threat intelligence feed update."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_intel_manifest (
                    feed_id, version, sequence, signatures_count, advisories_count,
                    publisher, signature_valid, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (feed_id, version, sequence, signatures_count, advisories_count, publisher, signature_valid))
            conn.commit()

    def get_threat_intel_status(self) -> Optional[Dict[str, Any]]:
        """Retrieve most recent threat intelligence manifest status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT feed_id, version, sequence, signatures_count, advisories_count,
                       publisher, signature_valid, updated_at
                FROM threat_intel_manifest
                ORDER BY sequence DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            return dict(row) if row else None



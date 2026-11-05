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

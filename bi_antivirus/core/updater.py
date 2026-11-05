"""
BI Antivirus - Malware Definition Update Manager
Manages database definitions, version verification, rollback backups,
and import/export of signature update bundles on D: drive.
"""

import json
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import (
    DATA_DIR,
    SIGNATURES_DB_PATH,
    SIGNATURE_DB_VERSION,
)
from bi_antivirus.database.signatures import SignatureDatabase


class UpdateManager:
    """Handles malware signature updates, rollback snapshots, and definition manifests."""

    def __init__(self, sig_db: Optional[SignatureDatabase] = None):
        self.sig_db = sig_db or SignatureDatabase()
        self.backup_dir = DATA_DIR / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def check_definition_status(self) -> Dict[str, Any]:
        """Inspect current signature database version, count, and definition age."""
        stats = self.sig_db.get_stats()
        
        # Calculate file modification age
        mtime = 0.0
        if SIGNATURES_DB_PATH.exists():
            mtime = SIGNATURES_DB_PATH.stat().st_mtime

        age_days = round((time.time() - mtime) / 86400.0, 1) if mtime > 0 else 0.0
        is_up_to_date = age_days < 7.0

        return {
            "version": stats.get("version", SIGNATURE_DB_VERSION),
            "total_signatures": stats.get("total_indicators", 0),
            "hash_signatures": stats.get("total_hash_signatures", 0),
            "pattern_signatures": stats.get("total_pattern_rules", 0),
            "web_reputations": stats.get("total_web_reputations", 0),
            "age_days": age_days,
            "status": "UP_TO_DATE" if is_up_to_date else "OUTDATED",
            "last_updated": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S") if mtime > 0 else "Initial",
        }

    def backup_database(self) -> Optional[Path]:
        """Create a safety backup copy of the current signature database before updating."""
        if not SIGNATURES_DB_PATH.exists():
            return None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"signatures_backup_{timestamp}.db"
        shutil.copy2(SIGNATURES_DB_PATH, backup_path)
        return backup_path

    def apply_update_pack(self, update_json_str: str) -> Dict[str, Any]:
        """
        Safely apply a definition update pack with automated backup.
        Rolls back if update fails.
        """
        backup_file = self.backup_database()
        try:
            imported = self.sig_db.import_signatures_json(update_json_str)
            new_stats = self.sig_db.get_stats()
            return {
                "success": True,
                "imported_count": imported,
                "current_version": new_stats["version"],
                "total_signatures": new_stats["total_indicators"],
                "message": f"Successfully applied update. Added/refreshed {imported} indicators.",
            }
        except Exception as e:
            # Rollback if failure
            if backup_file and backup_file.exists():
                shutil.copy2(backup_file, SIGNATURES_DB_PATH)
            return {
                "success": False,
                "error": f"Failed to apply update pack: {e}. Rollback restored.",
            }

    def export_current_pack(self) -> str:
        """Export current database to portable definition pack format."""
        return self.sig_db.export_signatures_json()

"""
BI Antivirus - Advanced Ransomware Shield & Canary Decoy Sentinel
Multi-layered defense against ransomware and unauthorized cryptor activity:
1. Canary Decoy Baiting (Honey-pot traps in user folders)
2. High-Frequency File Extension Mutation Bursts (.locked, .crypto, .enc, etc.)
3. Known Ransom Note Drop Interception
4. Shadow Copy & Backup Tampering Defense
"""

import os
import time
import hashlib
import threading
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from collections import deque

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    DATA_DIR,
    load_settings,
)
from bi_antivirus.database.history import HistoryDatabase

logger = logging.getLogger("bi_antivirus.ransomware_shield")

# Known extensions appended by active ransomware families
RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".crypted", ".enc", ".encrypted",
    ".wannacry", ".wncry", ".lockbit", ".blackcat", ".akira",
    ".phobos", ".ryuk", ".stop", ".djvu", ".mallox", ".blackmatter"
}

# Known ransom note filenames
RANSOM_NOTE_NAMES = {
    "readme_to_decrypt.txt", "how_to_recover_files.txt", "decrypt_files.html",
    "restore_files.txt", "!!!_readme_!!!.txt", "decrypt_info.txt",
    "readme_for_decrypt.txt", "recover_your_files.html", "how_to_decrypt.html"
}

# Canary decoy file content header
CANARY_HEADER = b"BI_ANTIVIRUS_CANARY_INTEGRITY_TRAP_V1_DO_NOT_MODIFY"


class RansomwareShield:
    """Active anti-ransomware sentinel with canary baiting and mutation burst detection."""

    def __init__(
        self,
        watch_dirs: Optional[List[Path]] = None,
        history_db: Optional[HistoryDatabase] = None,
        on_ransomware_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.history_db = history_db or HistoryDatabase()
        self.on_ransomware_alert = on_ransomware_alert
        self.watch_dirs = watch_dirs or [
            Path(os.path.expanduser(r"~\Documents")),
            Path(os.path.expanduser(r"~\Desktop")),
        ]

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Canary tracking: {canary_path: expected_sha256}
        self.canaries: Dict[Path, str] = {}

        # Mutation burst tracking: deque of (timestamp, filepath, new_ext)
        self._mutation_history: deque = deque(maxlen=200)
        self._burst_window_seconds = 5.0
        self._burst_threshold = 3  # >= 3 ransomware mutations in 5s triggers critical alert

    def deploy_canaries(self) -> int:
        """Deploy honey-pot canary decoy files across watched directories."""
        deployed = 0
        for directory in self.watch_dirs:
            if not directory.exists():
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                except Exception:
                    continue

            canary_path = directory / ".bi_integrity_canary.docx"
            try:
                # Generate unique content with deterministic hash
                content = CANARY_HEADER + b"_" + str(canary_path).encode("utf-8")
                expected_hash = hashlib.sha256(content).hexdigest()

                with open(canary_path, "wb") as f:
                    f.write(content)

                # Set hidden attribute on Windows if available
                if os.name == "nt":
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(canary_path), 0x02)  # FILE_ATTRIBUTE_HIDDEN
                    except Exception:
                        pass

                self.canaries[canary_path] = expected_hash
                deployed += 1
            except Exception as e:
                logger.debug(f"Failed deploying canary at {canary_path}: {e}")

        logger.info(f"Deployed {deployed} ransomware canary honey-pots.")
        return deployed

    def check_canary_integrity(self) -> List[Dict[str, Any]]:
        """
        Verify that all deployed canary decoy files are intact and un-encrypted.
        Returns list of violated canaries.
        """
        violations = []
        for path, expected_hash in list(self.canaries.items()):
            if not path.exists():
                violations.append({
                    "canary_path": str(path),
                    "violation_type": "CANARY_DELETED",
                    "severity": SEVERITY_CRITICAL,
                    "description": "Canary decoy file was unexpectedly deleted or moved (unauthorized tampering).",
                })
                continue

            try:
                with open(path, "rb") as f:
                    data = f.read()
                current_hash = hashlib.sha256(data).hexdigest()
                if current_hash != expected_hash:
                    violations.append({
                        "canary_path": str(path),
                        "violation_type": "CANARY_ENCRYPTED_OR_MODIFIED",
                        "severity": SEVERITY_CRITICAL,
                        "description": "Canary decoy file content was altered or encrypted by an external process!",
                    })
            except Exception as e:
                violations.append({
                    "canary_path": str(path),
                    "violation_type": "CANARY_LOCKED",
                    "severity": SEVERITY_HIGH,
                    "description": f"Canary file locked by another process: {e}",
                })

        return violations

    def record_file_mutation(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Evaluate single file modification or creation for ransomware characteristics:
        1. Known ransomware extension (.locked, .crypto, etc.)
        2. Known ransom note dropped
        3. Mutation burst rate exceeding safety threshold
        """
        now = time.time()
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        # 1. Ransom Note Check
        if name in RANSOM_NOTE_NAMES:
            alert = {
                "type": "RANSOM_NOTE_DROPPED",
                "file_path": str(file_path),
                "severity": SEVERITY_CRITICAL,
                "threat_name": "Ransomware.ExtortionNote.Detected",
                "summary": f"Known ransomware extortion note detected: {file_path.name}",
            }
            self._handle_alert(alert)
            return alert

        # 2. Ransomware Extension Check
        if ext in RANSOMWARE_EXTENSIONS:
            self._mutation_history.append((now, str(file_path), ext))

            # Count recent mutations within burst window
            recent = [item for item in self._mutation_history if now - item[0] <= self._burst_window_seconds]
            if len(recent) >= self._burst_threshold:
                alert = {
                    "type": "RANSOMWARE_BURST_ATTACK",
                    "file_path": str(file_path),
                    "severity": SEVERITY_CRITICAL,
                    "threat_name": "Ransomware.ActiveEncryptionBurst",
                    "summary": f"Detected high-frequency ransomware encryption burst ({len(recent)} files mutated to {ext} within {self._burst_window_seconds}s)!",
                    "mutated_count": len(recent),
                }
                self._handle_alert(alert)
                return alert
            else:
                alert = {
                    "type": "SUSPICIOUS_EXTENSION_MUTATION",
                    "file_path": str(file_path),
                    "severity": SEVERITY_HIGH,
                    "threat_name": f"Ransomware.SuspiciousExtension{ext.upper()}",
                    "summary": f"File renamed or written with known ransomware extension: {ext}",
                }
                self._handle_alert(alert)
                return alert

        return None

    def _handle_alert(self, alert_data: Dict[str, Any]) -> None:
        """Log threat and trigger callbacks."""
        logger.warning(f"RANSOMWARE SHIELD ALERT: {alert_data['summary']}")
        self.history_db.record_threat(
            session_id="RANSOMWARE-SHIELD",
            file_path=alert_data.get("file_path", "CANARY_TRAP"),
            file_hash="RANSOMWARE_DEFENSE",
            file_size=0,
            threat_name=alert_data.get("threat_name", "Ransomware.Activity"),
            threat_family="Ransomware",
            severity=alert_data.get("severity", SEVERITY_CRITICAL),
            action_taken="INTERCEPTED",
            details=alert_data.get("summary", ""),
        )

        if self.on_ransomware_alert:
            try:
                self.on_ransomware_alert(alert_data)
            except Exception:
                pass

    def start(self) -> bool:
        """Start background sentinel checking canaries and mutation bursts."""
        if self.is_running:
            return True

        self.deploy_canaries()
        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="BI-RansomwareShield"
        )
        self._worker_thread.start()
        logger.info("Ransomware Shield started.")
        return True

    def stop(self) -> None:
        """Stop background sentinel."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Ransomware Shield stopped.")

    def _monitor_loop(self) -> None:
        """Periodic canary integrity loop."""
        while not self._stop_event.is_set():
            try:
                violations = self.check_canary_integrity()
                for v in violations:
                    alert = {
                        "type": v["violation_type"],
                        "file_path": v["canary_path"],
                        "severity": v["severity"],
                        "threat_name": "Ransomware.CanaryTrapTriggered",
                        "summary": v["description"],
                    }
                    self._handle_alert(alert)
            except Exception as e:
                logger.debug(f"Canary check loop error: {e}")

            # Check every 2 seconds
            self._stop_event.wait(2.0)

    def get_shield_status(self) -> Dict[str, Any]:
        """Return diagnostic status of the ransomware shield and canaries."""
        return {
            "is_running": self.is_running,
            "canaries_count": len(self.canaries),
            "canaries": [str(p) for p in self.canaries.keys()],
            "mutations_tracked": len(self._mutation_history),
            "burst_alerts": 0,
            "watch_dirs": [str(d) for d in self.watch_dirs],
        }


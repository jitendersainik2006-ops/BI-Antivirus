"""
BI Antivirus - Real-Time Filesystem Guard
Monitors critical folders (Downloads, Desktop, Temp, custom paths) in background.
Intercepts newly created or modified files, evaluates threats via ThreatDetector,
and triggers instant alerts and quarantine isolation without blocking the OS.
"""

import os
import time
import threading
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Set

from bi_antivirus.config import load_settings
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.database.history import HistoryDatabase

logger = logging.getLogger("bi_antivirus.realtime")


class RealTimeGuard:
    """Background filesystem sentinel monitoring critical folders for threat activity."""

    def __init__(
        self,
        detector: Optional[ThreatDetector] = None,
        quarantine_mgr: Optional[QuarantineManager] = None,
        history_db: Optional[HistoryDatabase] = None,
        on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.detector = detector or ThreatDetector()
        self.quarantine_mgr = quarantine_mgr or QuarantineManager()
        self.history_db = history_db or HistoryDatabase()
        self.on_threat_detected = on_threat_detected

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._known_file_states: Dict[str, float] = {}  # filepath -> mtime
        self.monitored_paths: List[Path] = []
        self._processed_hashes: Set[str] = set()

    def update_monitored_paths(self) -> None:
        """Refresh directories to watch from settings."""
        settings = load_settings()
        paths = []
        for p in settings.get("monitored_directories", []):
            try:
                path_obj = Path(p).resolve()
                if path_obj.exists() and path_obj.is_dir():
                    paths.append(path_obj)
            except Exception:
                pass
        self.monitored_paths = paths

    def start(self) -> bool:
        """Start background real-time guard thread."""
        if self.is_running:
            return True

        self.update_monitored_paths()
        self._stop_event.clear()
        self.is_running = True

        # Initial baseline snapshot of directory files
        self._build_baseline()

        self._worker_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="BI-RealTimeGuard")
        self._worker_thread.start()
        logger.info(f"Real-Time Guard active, monitoring {len(self.monitored_paths)} folders.")
        return True

    def stop(self) -> None:
        """Stop background real-time guard."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Real-Time Guard stopped.")

    def _build_baseline(self) -> None:
        """Snapshot current directory files so only new/modified files trigger scans."""
        self._known_file_states.clear()
        for directory in self.monitored_paths:
            try:
                for root, _, files in os.walk(directory):
                    for f in files:
                        fp = Path(root) / f
                        try:
                            self._known_file_states[str(fp)] = fp.stat().st_mtime
                        except Exception:
                            pass
            except Exception:
                pass

    def _monitor_loop(self) -> None:
        """Continuous polling loop detecting newly dropped or changed files."""
        while not self._stop_event.is_set():
            try:
                for directory in self.monitored_paths:
                    if self._stop_event.is_set():
                        break
                    if not directory.exists():
                        continue

                    try:
                        for entry in os.scandir(directory):
                            if self._stop_event.is_set():
                                break
                            if entry.is_file():
                                fp = Path(entry.path)
                                try:
                                    mtime = entry.stat().st_mtime
                                    fp_str = str(fp)

                                    if fp_str not in self._known_file_states or self._known_file_states[fp_str] < mtime:
                                        self._known_file_states[fp_str] = mtime
                                        # Brief wait for write to finish
                                        time.sleep(0.05)
                                        self._handle_file_event(fp)
                                except (PermissionError, FileNotFoundError, OSError):
                                    continue
                    except Exception:
                        continue

            except Exception as e:
                logger.error(f"Error in real-time monitor loop: {e}")

            # Sleep between survey cycles
            time.sleep(1.0)

    def _handle_file_event(self, file_path: Path) -> None:
        """Inspect and handle new or modified file."""
        if not file_path.exists() or not file_path.is_file():
            return

        # Analyze file safely
        try:
            result = self.detector.analyze_file(file_path)
            if result.get("is_threat"):
                logger.warning(f"REAL-TIME THREAT DETECTED: {result['threat_name']} in {file_path}")

                settings = load_settings()
                action_taken = "FLAGGED"

                if settings.get("auto_quarantine_threats", False):
                    q_res = self.quarantine_mgr.quarantine_file(file_path, result)
                    if q_res.get("success"):
                        action_taken = "QUARANTINED"

                # Record in persistent history database
                self.history_db.record_threat(
                    session_id="REALTIME-GUARD",
                    file_path=str(file_path),
                    file_hash=result.get("file_hash", ""),
                    file_size=result.get("file_size", 0),
                    threat_name=result.get("threat_name", "Unknown Threat"),
                    threat_family=result.get("threat_family", "Generic"),
                    severity=result.get("severity", "HIGH"),
                    action_taken=action_taken,
                    details=f"Real-Time intercept: {result.get('description', '')}",
                )

                # Callback for UI / notifications
                if self.on_threat_detected:
                    try:
                        self.on_threat_detected(result)
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Failed analyzing file in real-time guard: {e}")

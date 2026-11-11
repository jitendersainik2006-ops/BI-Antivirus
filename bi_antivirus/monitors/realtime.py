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

from bi_antivirus.config import (
    load_settings,
    DATA_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    QUARANTINE_VAULT_DIR,
    PROJECT_ROOT,
)
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.ml_engine import LocalMLEngine

logger = logging.getLogger("bi_antivirus.realtime")


class RealTimeGuard:
    """
    Background filesystem sentinel monitoring critical folders for threat activity.
    Features:
    - Event Debouncing: Buffers rapid successive writes to ensure complete file writes before analysis.
    - Priority Scanning: High-priority queue for volatile ingress directories (%TEMP%, Downloads).
    - Self-Event Suppression: Suppresses internal file I/O from logs, quarantine, and database writes.
    - Local ML Static Classification: Leverages on-device ML model on dropped Windows PE binaries.
    """

    def __init__(
        self,
        detector: Optional[ThreatDetector] = None,
        quarantine_mgr: Optional[QuarantineManager] = None,
        history_db: Optional[HistoryDatabase] = None,
        ml_engine: Optional[LocalMLEngine] = None,
        on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None,
        debounce_window: float = 0.35,
    ):
        self.detector = detector or ThreatDetector()
        self.quarantine_mgr = quarantine_mgr or QuarantineManager()
        self.history_db = history_db or HistoryDatabase()
        self.ml_engine = ml_engine or LocalMLEngine()
        self.on_threat_detected = on_threat_detected
        self.debounce_window = debounce_window

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._known_file_states: Dict[str, float] = {}  # filepath -> mtime
        self.monitored_paths: List[Path] = []
        self.priority_paths: List[Path] = []
        self._processed_hashes: Set[str] = set()

        # Debounce tracking: filepath -> (first_seen, last_seen, last_size)
        self._debounce_queue: Dict[str, Tuple[float, float, int]] = {}
        self._lock = threading.Lock()

        # Telemetry metrics
        self.events_processed = 0
        self.threats_detected = 0
        self.suppressed_self_events = 0

        # Self-event suppression prefixes
        self._suppressed_prefixes = [
            DATA_DIR.resolve(),
            LOGS_DIR.resolve(),
            QUARANTINE_DIR.resolve(),
            QUARANTINE_VAULT_DIR.resolve(),
            (PROJECT_ROOT / ".git").resolve(),
        ]

    def _is_self_event(self, path: Path) -> bool:
        """Check if file event is generated internally by BI Antivirus."""
        try:
            resolved = path.resolve()
            res_str = str(resolved).lower()
            for prefix in self._suppressed_prefixes:
                if res_str.startswith(str(prefix).lower()):
                    return True
        except Exception:
            pass
        return False

    def update_monitored_paths(self) -> None:
        """Refresh directories to watch from settings and identify priority tiers."""
        settings = load_settings()
        paths = []
        prio = []

        # Standard system ingress paths
        user_home = Path.home()
        standard_ingress = [
            user_home / "Downloads",
            Path(os.environ.get("TEMP", r"C:\Windows\Temp")),
            user_home / "AppData" / "Local" / "Temp",
        ]

        raw_dirs = settings.get("monitored_directories", [])
        for p in raw_dirs:
            try:
                path_obj = Path(p).resolve()
                if path_obj.exists() and path_obj.is_dir() and not self._is_self_event(path_obj):
                    paths.append(path_obj)
            except Exception:
                pass

        # Identify priority paths (%TEMP% and Downloads)
        for p in paths:
            p_str = str(p).lower()
            if "download" in p_str or "temp" in p_str:
                prio.append(p)

        self.monitored_paths = paths
        self.priority_paths = prio

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
        logger.info(f"Real-Time Guard active, monitoring {len(self.monitored_paths)} folders ({len(self.priority_paths)} priority).")
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
                        if self._is_self_event(fp):
                            continue
                        try:
                            self._known_file_states[str(fp)] = fp.stat().st_mtime
                        except Exception:
                            pass
            except Exception:
                pass

    def _enqueue_event(self, file_path: Path, mtime: float, size: int) -> None:
        """Enqueue or update an event in the debounce queue."""
        fp_str = str(file_path)
        now = time.time()
        with self._lock:
            if fp_str in self._debounce_queue:
                first_seen, _, _ = self._debounce_queue[fp_str]
                self._debounce_queue[fp_str] = (first_seen, now, size)
            else:
                self._debounce_queue[fp_str] = (now, now, size)

    def _process_debounce_queue(self) -> None:
        """Drain files that have settled (no writes within debounce window)."""
        now = time.time()
        ready_files = []

        with self._lock:
            for fp_str, (first_seen, last_seen, last_size) in list(self._debounce_queue.items()):
                if now - last_seen >= self.debounce_window:
                    p = Path(fp_str)
                    try:
                        curr_size = p.stat().st_size if p.exists() else -1
                        if curr_size == last_size:
                            ready_files.append(p)
                            del self._debounce_queue[fp_str]
                        else:
                            # Still changing size: postpone
                            self._debounce_queue[fp_str] = (first_seen, now, curr_size)
                    except Exception:
                        del self._debounce_queue[fp_str]

        for p in ready_files:
            self._handle_file_event(p)

    def _monitor_loop(self) -> None:
        """Continuous polling loop detecting newly dropped or changed files."""
        while not self._stop_event.is_set():
            try:
                # 1. Process priority paths first (Downloads, Temp)
                ordered_dirs = self.priority_paths + [p for p in self.monitored_paths if p not in self.priority_paths]

                for directory in ordered_dirs:
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
                                if self._is_self_event(fp):
                                    self.suppressed_self_events += 1
                                    continue

                                try:
                                    st = entry.stat()
                                    mtime = st.st_mtime
                                    size = st.st_size
                                    fp_str = str(fp)

                                    if fp_str not in self._known_file_states or self._known_file_states[fp_str] < mtime:
                                        self._known_file_states[fp_str] = mtime
                                        self._enqueue_event(fp, mtime, size)
                                except (PermissionError, FileNotFoundError, OSError):
                                    continue
                    except Exception:
                        continue

                # 2. Drain debounce queue
                self._process_debounce_queue()

            except Exception as e:
                logger.error(f"Error in real-time monitor loop: {e}")

            # Sleep between survey cycles
            time.sleep(0.5)

    def _handle_file_event(self, file_path: Path) -> None:
        """Inspect and handle new or modified file."""
        if not file_path.exists() or not file_path.is_file():
            return

        if self._is_self_event(file_path):
            self.suppressed_self_events += 1
            return

        self.events_processed += 1

        # Analyze file safely
        try:
            result = self.detector.analyze_file(file_path)
            is_threat = result.get("is_threat", False)

            # Optional local ML static evaluation for PE binaries
            if not is_threat and file_path.suffix.lower() in (".exe", ".dll", ".sys"):
                try:
                    ml_pred = self.ml_engine.predict(file_path=file_path)
                    if ml_pred.verdict == "MALICIOUS":
                        is_threat = True
                        result["is_threat"] = True
                        result["threat_name"] = f"ML.Heuristics.SuspiciousPE.{ml_pred.model_version}"
                        result["threat_family"] = "MachineLearning"
                        result["severity"] = "HIGH"
                        result["description"] = f"Local ML inference flagged executable (prob={ml_pred.probability:.2f})"
                except Exception as ex:
                    logger.debug(f"Real-time ML evaluation skipped: {ex}")

            if is_threat:
                self.threats_detected += 1
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

    def get_guard_status(self) -> Dict[str, Any]:
        """Return diagnostic metrics of the real-time guard."""
        return {
            "is_running": self.is_running,
            "monitored_paths_count": len(self.monitored_paths),
            "priority_paths_count": len(self.priority_paths),
            "events_processed": self.events_processed,
            "threats_detected": self.threats_detected,
            "suppressed_self_events": self.suppressed_self_events,
            "debounce_queue_size": len(self._debounce_queue),
            "known_files_count": len(self._known_file_states),
        }

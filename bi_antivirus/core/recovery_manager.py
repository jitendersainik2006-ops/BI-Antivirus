"""
BI Antivirus - Application Lifecycle, Lock & Crash Recovery Manager
Handles:
- Single-instance lock file management (data/bi_antivirus.lock)
- Stale lock detection and crash identification across unexpected terminations
- Safe startup recovery: SQLite WAL checkpoints, PRAGMA integrity verification
- Orphaned quarantine temporary file cleanup
- Graceful shutdown orchestration (signal handlers for SIGINT, SIGTERM, atexit)
- Records structured recovery logs on D: drive
"""

import os
import sys
import time
import json
import signal
import atexit
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.config import (
    DATA_DIR,
    QUARANTINE_VAULT_DIR,
    HISTORY_DB_PATH,
    SIGNATURES_DB_PATH,
    QUARANTINE_DB_PATH,
)
from bi_antivirus.core.logger import SecurityLogger

logger = logging.getLogger("bi_antivirus.recovery")


class CrashRecoveryManager:
    """Manages application process locks, detects crash scenarios, and performs automated startup recovery."""

    def __init__(self, data_dir: Optional[Path] = None, logger_instance: Optional[SecurityLogger] = None):
        self.data_dir = Path(data_dir or DATA_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock_file = self.data_dir / "bi_antivirus.lock"
        self.sec_logger = logger_instance or SecurityLogger()
        self._is_locked_by_me = False

    def is_pid_active(self, pid: int) -> bool:
        """Check if a process with given PID is currently active on Windows/host."""
        if pid <= 0:
            return False

        if os.name == "nt":
            try:
                import ctypes
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                STILL_ACTIVE = 259
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if handle:
                    exit_code = ctypes.c_ulong()
                    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                    kernel32.CloseHandle(handle)
                    return exit_code.value == STILL_ACTIVE
                return False
            except Exception:
                pass

        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def acquire_lock(self) -> Tuple[bool, str]:
        """
        Attempt to acquire the application single-instance lock file.
        Returns: (success: bool, status_message: str)
        """
        current_pid = os.getpid()

        if self.lock_file.exists():
            try:
                with open(self.lock_file, "r", encoding="utf-8") as f:
                    lock_data = json.load(f)
                locked_pid = lock_data.get("pid", 0)

                if locked_pid == current_pid:
                    self._is_locked_by_me = True
                    return True, "Lock already held by current process"

                if self.is_pid_active(locked_pid):
                    return False, f"BI Antivirus is already active in process {locked_pid}."
                else:
                    logger.warning(f"Detected stale lock from inactive PID {locked_pid}. Cleared stale lock.")
                    self.lock_file.unlink(missing_ok=True)
            except Exception:
                self.lock_file.unlink(missing_ok=True)

        # Write fresh lock
        payload = {
            "pid": current_pid,
            "acquired_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": time.time(),
            "executable": sys.executable,
        }

        try:
            with open(self.lock_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self._is_locked_by_me = True
            return True, f"Lock successfully acquired for PID {current_pid}"
        except Exception as e:
            return False, f"Failed to acquire lock: {e}"

    def release_lock(self) -> bool:
        """Release application lock file on clean shutdown."""
        if self._is_locked_by_me and self.lock_file.exists():
            try:
                self.lock_file.unlink(missing_ok=True)
                self._is_locked_by_me = False
                return True
            except Exception as e:
                logger.debug(f"Failed to release lock: {e}")
                return False
        return False

    def perform_startup_recovery(self) -> Dict[str, Any]:
        """
        Inspect environment for remnants of unexpected shutdown and execute recovery:
        - Detect if previous shutdown was unclean
        - Run SQLite WAL checkpoints and integrity checks
        - Prune orphaned .tmp vault files
        """
        recovery_events = []
        stale_recovered = False

        # 1. Check for stale lock indicating prior crash
        if self.lock_file.exists():
            try:
                with open(self.lock_file, "r", encoding="utf-8") as f:
                    lock_data = json.load(f)
                prev_pid = lock_data.get("pid", 0)
                if prev_pid != os.getpid() and not self.is_pid_active(prev_pid):
                    stale_recovered = True
                    msg = f"Recovered from previous unexpected termination of PID {prev_pid} (acquired {lock_data.get('acquired_at')})"
                    recovery_events.append(msg)
                    self.sec_logger.log_event("WARNING", "RECOVERY", msg)
                    self.lock_file.unlink(missing_ok=True)
            except Exception:
                pass

        # 2. Database WAL checkpoint and integrity verification
        db_checks = {}
        for db_name, db_p in [
            ("history", Path(HISTORY_DB_PATH)),
            ("signatures", Path(SIGNATURES_DB_PATH)),
            ("quarantine", Path(QUARANTINE_DB_PATH)),
        ]:
            if db_p.exists():
                try:
                    import sqlite3
                    conn = sqlite3.connect(str(db_p), timeout=10.0)
                    conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                    cursor = conn.cursor()
                    cursor.execute("PRAGMA integrity_check;")
                    res = cursor.fetchone()
                    conn.close()
                    ok = (res and res[0] == "ok")
                    db_checks[db_name] = {"status": "OK" if ok else "WARN", "detail": res[0] if res else "Unknown"}
                except Exception as e:
                    db_checks[db_name] = {"status": "ERROR", "detail": str(e)}

        # 3. Clean orphaned temporary files in quarantine vault
        orphaned_cleaned = 0
        vault_dir = Path(QUARANTINE_VAULT_DIR)
        if vault_dir.exists():
            for tmp in vault_dir.glob("*.tmp"):
                try:
                    tmp.unlink(missing_ok=True)
                    orphaned_cleaned += 1
                except Exception:
                    pass

        if orphaned_cleaned > 0:
            msg = f"Purged {orphaned_cleaned} orphaned temporary quarantine vault files"
            recovery_events.append(msg)
            self.sec_logger.log_event("INFO", "RECOVERY", msg)

        # 4. Acquire lock for current process
        lock_ok, lock_msg = self.acquire_lock()

        return {
            "status": "RECOVERED" if stale_recovered else "NORMAL_STARTUP",
            "previous_unclean_shutdown": stale_recovered,
            "lock_acquired": lock_ok,
            "lock_message": lock_msg,
            "database_checks": db_checks,
            "orphaned_tmp_files_cleaned": orphaned_cleaned,
            "recovery_events": recovery_events,
        }

    def register_shutdown_hooks(self) -> None:
        """Register clean shutdown handlers for process termination signals."""
        atexit.register(self.release_lock)

        def _sig_handler(signum, frame):
            logger.info(f"Received signal {signum}. Initiating clean shutdown...")
            self.release_lock()
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)
        except (ValueError, AttributeError):
            pass

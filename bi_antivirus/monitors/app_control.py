"""
BI Antivirus - Enterprise Application Control Sentinel
Enforces enterprise binary execution policies, whitelisting, and untrusted directory lockdown:
1. Cryptographic SHA-256 binary hash whitelisting and blacklisting.
2. Untrusted directory execution lockdown (blocks/audits binaries spawned from Temp, AppData, Downloads, Public).
3. Authenticode digital signature publisher policy enforcement.
4. Critical Windows system process and self-protection exclusions.
5. LOLBin (Living-off-the-Land) interpreter lockdown (PowerShell, WScript, CScript, MSHTA).
6. Dual Operational Modes:
   - AUDIT: Telemetry only, logs security events and raises UI warnings without process termination.
   - ENFORCE: Active enforcement via Win32 TerminateProcess post-spawn for unapproved binaries.
Clean-room implementation targeting Bitdefender GravityZone Application Control parity.
"""

import os
import sys
import time
import hashlib
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Tuple

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
)
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.authenticode import AuthenticodeVerifier
from bi_antivirus.core.policy_engine import (
    PolicyEngine,
    APP_MODE_AUDIT,
    APP_MODE_ENFORCE,
)

logger = logging.getLogger("bi_antivirus.app_control")

KNOWN_LOLBINS = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "certutil.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe"
}

# Critical Windows binaries that must NEVER be terminated by Application Control
CRITICAL_WINDOWS_BINARIES = {
    "svchost.exe", "explorer.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "winlogon.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe"
}


class ApplicationControlSentinel:
    """Monitors and enforces executable execution policies across the endpoint."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        history_db: Optional[HistoryDatabase] = None,
        on_violation: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.history_db = history_db or HistoryDatabase()
        self.on_violation = on_violation
        self.verifier = AuthenticodeVerifier

        self._evaluated_cache: Dict[str, Tuple[str, str, float]] = {}  # {path: (status, reason, timestamp)}
        self._cache_lock = threading.Lock()

    @staticmethod
    def calculate_sha256(file_path: Path) -> Optional[str]:
        """Compute SHA-256 hash of an executable binary."""
        try:
            sha = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception as e:
            logger.debug(f"Failed calculating hash for {file_path}: {e}")
            return None

    def evaluate_executable(self, file_path: str) -> Dict[str, Any]:
        """
        Inspect an executable file against enterprise Application Control policy.
        Returns: Dict containing verdict ('ALLOW', 'BLOCK', 'AUDIT'), hash, publisher, and reason.
        """
        p = Path(file_path)
        if not p.is_file():
            return {
                "file_path": file_path,
                "status": "ALLOW",
                "reason": "File does not exist or is not a regular file.",
                "sha256": None,
                "publisher": None,
            }

        exe_name = p.name.lower()

        # Critical System Exclusions: Never block genuine Windows core binaries in System32
        norm_path = str(p.resolve()).lower()
        if exe_name in CRITICAL_WINDOWS_BINARIES and ("system32" in norm_path or "syswow64" in norm_path):
            return {
                "file_path": str(p),
                "file_name": p.name,
                "status": "ALLOW",
                "reason": "Critical Windows core system binary protected from policy blocking.",
                "sha256": None,
                "publisher": "Microsoft Windows",
                "is_lolbin": False,
            }

        # Check cache (10.0s TTL)
        norm_key = norm_path
        now = time.time()
        with self._cache_lock:
            if norm_key in self._evaluated_cache:
                cached_status, cached_reason, cached_time = self._evaluated_cache[norm_key]
                if now - cached_time < 10.0:
                    return {
                        "file_path": file_path,
                        "file_name": p.name,
                        "status": cached_status,
                        "reason": cached_reason,
                        "cached": True,
                    }

        # 1. Compute Hash
        file_hash = self.calculate_sha256(p)

        # 2. Check Digital Signature & Publisher
        auth_info = self.verifier.verify_file_signature(p)
        publisher = auth_info.get("publisher") if auth_info.get("is_signed") else None

        # 3. Check LOLBin identity
        is_lolbin = exe_name in KNOWN_LOLBINS

        # 4. Evaluate against PolicyEngine
        verdict, reason = self.policy_engine.evaluate_application_policy(
            file_path=str(p),
            sha256_hash=file_hash,
            publisher=publisher,
            is_lolbin=is_lolbin,
        )

        result = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": str(p),
            "file_name": p.name,
            "status": verdict,
            "reason": reason,
            "sha256": file_hash,
            "is_signed": auth_info.get("is_signed", False),
            "publisher": publisher,
            "is_lolbin": is_lolbin,
        }

        # Record violations (BLOCK or AUDIT) into database
        if verdict in ("BLOCK", "AUDIT"):
            severity = SEVERITY_CRITICAL if verdict == "BLOCK" else SEVERITY_HIGH
            try:
                self.history_db.record_event(
                    event_type=f"APP_CONTROL_{verdict}",
                    source="APPLICATION_CONTROL",
                    severity=severity,
                    details=f"Application {p.name} [{verdict}]: {reason} (Hash: {file_hash[:12] if file_hash else 'N/A'})",
                )
            except Exception as e:
                logger.debug(f"Failed logging app control event: {e}")

            if self.on_violation:
                try:
                    self.on_violation(result)
                except Exception as e:
                    logger.debug(f"Error in app control violation callback: {e}")

        # Update cache
        with self._cache_lock:
            self._evaluated_cache[norm_key] = (verdict, reason, now)

        logger.info(f"Application Control verdict for {p.name}: {verdict} - {reason}")
        return result

    def terminate_process(self, pid: int) -> Tuple[bool, str]:
        """
        Safely terminate an unapproved/blocked process using native Win32 TerminateProcess.
        Guarded against terminating self, system idle, or critical system processes.
        """
        if pid == os.getpid() or pid <= 4:
            return False, "Cannot terminate self or system idle/init processes."

        if os.name != "nt":
            try:
                import signal
                os.kill(pid, signal.SIGTERM)
                return True, f"Process PID {pid} terminated via SIGTERM."
            except Exception as e:
                return False, f"Failed terminating PID {pid}: {e}"

        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_TERMINATE = 0x0001
            h_proc = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not h_proc:
                return False, f"Could not acquire PROCESS_TERMINATE handle for PID {pid} (Access denied or dead process)."

            success = kernel32.TerminateProcess(h_proc, 1)
            kernel32.CloseHandle(h_proc)

            if success:
                logger.info(f"Terminated unapproved process PID {pid} under ENFORCE policy.")
                return True, f"Process PID {pid} successfully terminated by Application Control."
            else:
                return False, f"TerminateProcess call failed for PID {pid}."
        except Exception as e:
            return False, f"Exception terminating PID {pid}: {e}"

    def evaluate_process(self, pid: int, exe_path: str, cmdline: str = "") -> Dict[str, Any]:
        """
        Evaluate an active process against Application Control rules.
        If in ENFORCE mode and verdict is BLOCK, executes immediate process termination.
        """
        res = self.evaluate_executable(exe_path)
        res["pid"] = pid
        res["cmdline"] = cmdline

        mode = self.policy_engine.current_policy.get("application_control", {}).get("mode", APP_MODE_AUDIT)
        res["mode"] = mode
        should_terminate = (res.get("status") == "BLOCK" and mode == APP_MODE_ENFORCE)
        res["should_terminate"] = should_terminate

        # Execute genuine process termination if in ENFORCE mode
        if should_terminate:
            term_success, term_detail = self.terminate_process(pid)
            res["terminated"] = term_success
            res["termination_detail"] = term_detail

            try:
                self.history_db.record_event(
                    event_type="APP_CONTROL_TERMINATED",
                    source="APPLICATION_CONTROL",
                    severity=SEVERITY_CRITICAL,
                    details=f"Terminated PID {pid} ({res.get('file_name')}): {term_detail}",
                )
            except Exception as e:
                logger.debug(f"Failed logging process termination event: {e}")
        else:
            res["terminated"] = False
            res["termination_detail"] = "Termination not requested (Audit mode or Allowed)."

        return res

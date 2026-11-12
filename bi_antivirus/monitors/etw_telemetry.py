"""
BI Antivirus - Event Tracing for Windows (ETW) Telemetry Probe
Audits Windows ETW security providers, checks provider availability and OS compatibility,
validates session creation permissions, and provides safe, read-only diagnostic telemetry
with automatic fallback to native Win32 Toolhelp32 process snapshotting.
"""

import os
import sys
import subprocess
import time
import threading
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

from bi_antivirus.core.privilege_manager import is_user_admin

logger = logging.getLogger("bi_antivirus.etw_telemetry")

# Known defensive Windows ETW providers
DEFENSIVE_ETW_PROVIDERS = {
    "Microsoft-Windows-Kernel-Process": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    "Microsoft-Windows-Threat-Intelligence": "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}",
    "Microsoft-Windows-DNS-Client": "{1C950233-3226-42D0-90DA-E3169F8B337B}",
    "Microsoft-Windows-Kernel-Network": "{7DD42A49-5329-4832-8DFD-43D979153A88}",
}


class ETWTelemetryProbe:
    """Diagnostic probe for Windows Event Tracing capabilities and fallback coordination."""

    def __init__(self, check_registry_on_init: bool = True):
        self.is_windows = sys.platform == "win32"
        self._provider_cache: Dict[str, bool] = {}
        self._diagnostic_events: List[Dict[str, Any]] = []
        self._max_events = 200

        # Toolhelp32 snapshot state
        self._previous_snapshot: Dict[int, Dict[str, Any]] = {}
        self._monitor_running = False
        self._monitor_stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self.last_poll_duration_ms: float = 0.0
        self.total_polls: int = 0

        if check_registry_on_init and self.is_windows:
            self.refresh_provider_status()
            # Initialize baseline process snapshot
            self.capture_process_snapshot()

    def refresh_provider_status(self) -> Dict[str, bool]:
        """Probes the Windows OS to determine which defensive providers are registered."""
        if not self.is_windows:
            self._provider_cache = {p: False for p in DEFENSIVE_ETW_PROVIDERS}
            return self._provider_cache

        results = {}
        for provider_name in DEFENSIVE_ETW_PROVIDERS:
            results[provider_name] = self._check_provider_registered(provider_name)

        self._provider_cache = results
        return self._provider_cache

    def _check_provider_registered(self, provider_name: str) -> bool:
        """Query logman or Windows registry to confirm ETW provider registration."""
        try:
            cmd = ["logman", "query", "providers", provider_name]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            return proc.returncode == 0 and provider_name.lower() in proc.stdout.lower()
        except Exception:
            return False

    def list_active_trace_sessions(self) -> List[str]:
        """
        Query currently running ETW Event Trace Sessions using logman query -ets.
        Returns a list of active session names (e.g. NT Kernel Logger, EventLog-Application).
        """
        if not self.is_windows:
            return []

        sessions = []
        try:
            cmd = ["logman", "query", "-ets"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if proc.returncode == 0 and proc.stdout:
                lines = proc.stdout.splitlines()
                # Parse session names table
                in_table = False
                for line in lines:
                    line_str = line.strip()
                    if line_str.startswith("---"):
                        in_table = True
                        continue
                    if in_table and line_str:
                        if "command completed successfully" in line_str.lower():
                            break
                        parts = line_str.split(None, 1)
                        if parts:
                            sessions.append(parts[0])
        except Exception as e:
            logger.debug(f"Failed querying active ETW sessions: {e}")

        return sessions

    def can_start_kernel_trace(self) -> bool:
        """
        Verify if the current process token has sufficient rights to create
        a real-time ETW kernel trace session (requires Administrator or Performance Log Users).
        """
        return self.is_windows and is_user_admin()

    def capture_process_snapshot(self) -> Dict[int, Dict[str, Any]]:
        """
        Capture current system process tree snapshot using native Win32 Toolhelp32.
        Returns mapping of PID -> {pid, ppid, threads, exe}.
        """
        snapshot = {}
        if not self.is_windows:
            return snapshot

        h_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if h_snap == -1 or not h_snap:
            return snapshot

        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

            if ctypes.windll.kernel32.Process32FirstW(h_snap, ctypes.byref(pe)):
                while True:
                    snapshot[pe.th32ProcessID] = {
                        "pid": pe.th32ProcessID,
                        "ppid": pe.th32ParentProcessID,
                        "threads": pe.cntThreads,
                        "exe": pe.szExeFile,
                    }
                    if not ctypes.windll.kernel32.Process32NextW(h_snap, ctypes.byref(pe)):
                        break
        except Exception as e:
            logger.debug(f"Toolhelp32 snapshot error: {e}")
        finally:
            ctypes.windll.kernel32.CloseHandle(h_snap)

        with self._lock:
            self._previous_snapshot = snapshot

        return snapshot

    def poll_process_lifecycle_events(self) -> List[Dict[str, Any]]:
        """
        Compute snapshot differential to identify genuine process creation and termination events.
        Operates as a user-space Process Lifecycle Polling Engine (fallback) via Toolhelp32 snapshots.
        Note: True kernel ETW consumption requires Microsoft ELAM and PPL Antivirus EKU.
        """
        if not self.is_windows:
            return []

        t0 = time.perf_counter()
        current_snap = {}
        h_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if h_snap == -1 or not h_snap:
            return []

        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if ctypes.windll.kernel32.Process32FirstW(h_snap, ctypes.byref(pe)):
                while True:
                    current_snap[pe.th32ProcessID] = {
                        "pid": pe.th32ProcessID,
                        "ppid": pe.th32ParentProcessID,
                        "threads": pe.cntThreads,
                        "exe": pe.szExeFile,
                    }
                    if not ctypes.windll.kernel32.Process32NextW(h_snap, ctypes.byref(pe)):
                        break
        except Exception as e:
            logger.debug(f"Toolhelp32 differential scan failed: {e}")
            return []
        finally:
            ctypes.windll.kernel32.CloseHandle(h_snap)

        events = []
        with self._lock:
            prev = self._previous_snapshot

            # Detect newly started processes or PID reuse
            for pid, info in current_snap.items():
                if pid not in prev:
                    event = {
                        "timestamp": time.time(),
                        "event_type": "PROCESS_START",
                        "pid": pid,
                        "ppid": info["ppid"],
                        "image": info["exe"],
                        "threads": info["threads"],
                        "provider": "Toolhelp32PollingEngine",
                        "pid_reuse_detected": False,
                    }
                    events.append(event)
                    self.record_diagnostic_event("PROCESS_START", event)
                else:
                    # PID reuse check: same PID but different executable or parent PID
                    prev_info = prev[pid]
                    if (
                        info["exe"].lower() != prev_info.get("exe", "").lower()
                        or info["ppid"] != prev_info.get("ppid", 0)
                    ):
                        term_ev = {
                            "timestamp": time.time(),
                            "event_type": "PROCESS_TERMINATE",
                            "pid": pid,
                            "ppid": prev_info.get("ppid", 0),
                            "image": prev_info.get("exe", "unknown"),
                            "provider": "Toolhelp32PollingEngine",
                            "pid_reuse_detected": True,
                        }
                        events.append(term_ev)
                        self.record_diagnostic_event("PROCESS_TERMINATE", term_ev)

                        start_ev = {
                            "timestamp": time.time(),
                            "event_type": "PROCESS_START",
                            "pid": pid,
                            "ppid": info["ppid"],
                            "image": info["exe"],
                            "threads": info["threads"],
                            "provider": "Toolhelp32PollingEngine",
                            "pid_reuse_detected": True,
                        }
                        events.append(start_ev)
                        self.record_diagnostic_event("PROCESS_START", start_ev)

            # Detect terminated processes
            for pid, info in prev.items():
                if pid not in current_snap:
                    event = {
                        "timestamp": time.time(),
                        "event_type": "PROCESS_TERMINATE",
                        "pid": pid,
                        "ppid": info.get("ppid", 0),
                        "image": info.get("exe", "unknown"),
                        "provider": "Toolhelp32PollingEngine",
                        "pid_reuse_detected": False,
                    }
                    events.append(event)
                    self.record_diagnostic_event("PROCESS_TERMINATE", event)

            self._previous_snapshot = current_snap
            duration_ms = (time.perf_counter() - t0) * 1000.0
            self.last_poll_duration_ms = round(duration_ms, 2)
            self.total_polls += 1

        return events

    def start_fallback_monitor(self, interval: float = 2.0) -> None:
        """Launch background polling thread for continuous Toolhelp32 process tracking."""
        with self._lock:
            if self._monitor_running:
                return
            self._monitor_running = True
            self._monitor_stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                args=(interval,),
                daemon=True,
                name="Toolhelp32FallbackWorker",
            )
            self._monitor_thread.start()
            logger.info("Toolhelp32 process lifecycle monitoring started.")

    def stop_fallback_monitor(self) -> None:
        """Stop background process lifecycle polling thread."""
        with self._lock:
            if not self._monitor_running:
                return
            self._monitor_running = False
            self._monitor_stop_event.set()
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=3.0)
            logger.info("Toolhelp32 process lifecycle monitoring stopped.")

    def _monitor_loop(self, interval: float) -> None:
        while not self._monitor_stop_event.is_set():
            try:
                self.poll_process_lifecycle_events()
            except Exception as e:
                logger.debug(f"Error in process lifecycle poll: {e}")
            self._monitor_stop_event.wait(interval)

    def record_diagnostic_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Append a sanitized, non-PII diagnostic event to the probe buffer.
        Only metadata such as process ID, image base name, and timestamps are recorded.
        """
        sanitized = {
            "timestamp": details.get("timestamp", time.time()),
            "event_type": str(event_type),
            "pid": details.get("pid", 0),
            "image": Path(str(details.get("image", "unknown"))).name,
            "provider": details.get("provider", "DiagnosticProbe"),
        }
        with self._lock:
            self._diagnostic_events.append(sanitized)
            if len(self._diagnostic_events) > self._max_events:
                self._diagnostic_events.pop(0)

    def get_etw_status(self) -> Dict[str, Any]:
        """
        Returns structured diagnostic status regarding Windows ETW telemetry,
        provider registrations, permission states, active sessions, and fallback mechanisms.
        """
        if not self._provider_cache:
            self.refresh_provider_status()

        admin_allowed = self.can_start_kernel_trace()
        registered_count = sum(1 for is_reg in self._provider_cache.values() if is_reg)
        active_sessions = self.list_active_trace_sessions()

        if not self.is_windows:
            operational_status = "UNSUPPORTED_PLATFORM"
            message = "ETW is native to Microsoft Windows. Non-Windows environments use simulated telemetry."
        elif not admin_allowed:
            operational_status = "RESTRICTED_PERMISSIONS"
            message = (
                f"{registered_count} defensive ETW providers discovered on Windows. "
                "However, real-time ETW session creation requires an elevated Administrator token or "
                "Performance Log Users membership. Operating in Diagnostic Probe mode; "
                "Toolhelp32 process snapshotting is active as primary fallback."
            )
        else:
            operational_status = "PERMITTED_PROBE"
            message = (
                f"{registered_count} defensive ETW providers verified. Process has administrative rights. "
                "Note: Microsoft-Windows-Threat-Intelligence requires ELAM/PPL certificate for direct kernel consumption."
            )

        provider_details = []
        for name, guid in DEFENSIVE_ETW_PROVIDERS.items():
            is_reg = self._provider_cache.get(name, False)
            provider_details.append({
                "name": name,
                "guid": guid,
                "registered": is_reg,
                "requires_elam": "Threat-Intelligence" in name,
            })

        with self._lock:
            pids_tracked = len(self._previous_snapshot)
            events_count = len(self._diagnostic_events)
            recent_events = list(self._diagnostic_events[-10:])
            monitor_active = self._monitor_running
            last_lat = self.last_poll_duration_ms
            polls = self.total_polls

        return {
            "supported": self.is_windows,
            "operational_status": operational_status,
            "provider_count": len(DEFENSIVE_ETW_PROVIDERS),
            "registered_count": registered_count,
            "providers": provider_details,
            "can_start_trace": admin_allowed,
            "active_trace_sessions_count": len(active_sessions),
            "active_trace_sessions": active_sessions,
            "etw_kernel_consumer_active": False,
            "etw_kernel_requirement": "Direct kernel ETW TI subscription requires Microsoft ELAM and PPL Antivirus EKU.",
            "fallback_active": True,
            "fallback_mechanism": "Win32 Toolhelp32 Process Lifecycle Polling Engine (User-Space Fallback) & ReadDirectoryChangesW",
            "fallback_snapshot_pids_tracked": pids_tracked,
            "fallback_monitoring_active": monitor_active,
            "last_poll_duration_ms": last_lat,
            "total_polls": polls,
            "message": message,
            "diagnostic_events_count": events_count,
            "recent_events": recent_events,
        }

"""
BI Antivirus - Behavioral Process Monitor (Active Threat Sentinel)
Monitors running Windows processes for malicious behaviors, LOLBin abuse,
anomalous parent-child executions, and ransomware staging in real-time.
Non-destructive: audits process telemetry without kernel tampering or instability.
"""

import os
import sys
import time
import re
import subprocess
import threading
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Tuple

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
    load_settings,
)
from bi_antivirus.database.history import HistoryDatabase

logger = logging.getLogger("bi_antivirus.behavioral")

# High-risk parent applications that should never spawn shells or execution utilities
ANOMALOUS_PARENTS = {
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "outlook.exe": "Microsoft Outlook",
    "acrord32.exe": "Adobe Acrobat Reader",
    "acrobat.exe": "Adobe Acrobat",
    "wmiprvse.exe": "WMI Provider",
}

# Suspicious child binaries commonly used in droppers and living-off-the-land attacks
SUSPICIOUS_CHILDREN = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe",
    "bitsadmin.exe", "regsvr32.exe", "rundll32.exe", "curl.exe",
    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe"
}

# High-risk command-line patterns indicative of active exploitation or ransomware staging
SUSPICIOUS_CLI_INDICATORS = [
    (r"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,}", "PowerShell.EncodedCommand", 65),
    (r"(?i)downloadstring|downloaddata|downloadfile", "PowerShell.WebDownload", 50),
    (r"(?i)iex\s*\(|invoke-expression", "PowerShell.InvokeExpression", 45),
    (r"(?i)-windowstyle\s+hidden|-w\s+hidden", "Execution.HiddenWindow", 30),
    (r"(?i)vssadmin(\.exe)?\s+delete\s+shadows", "Ransomware.ShadowCopyDeletion", 80),
    (r"(?i)wbadmin(\.exe)?\s+delete\s+catalog", "Ransomware.BackupCatalogDeletion", 75),
    (r"(?i)bcdedit(\.exe)?\s+/set\s+.*bootstatuspolicy\s+ignoreallfailures", "Ransomware.BootPolicyTampering", 65),
    (r"(?i)certutil(\.exe)?\s+(-urlcache|-split|-f)\s+http", "Dropper.CertutilDownload", 60),
    (r"(?i)regsvr32(\.exe)?\s+.*scrobj\.dll", "DefenseEvasion.Squiblydoo", 65),
    (r"(?i)rundll32(\.exe)?\s+.*javascript:", "Dropper.Rundll32Script", 55),
]

# Sensitive user-writable directories where execution should be closely inspected
SUSPICIOUS_EXECUTION_DIRS = [
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
]


def _query_process_cmdline(pid: int) -> str:
    """
    Safely retrieves process command line using Windows native NtQueryInformationProcess
    (ProcessCommandLineInformation = 60).
    Requires only PROCESS_QUERY_LIMITED_INFORMATION (0x1000).
    Non-destructive: returns empty string if access denied or PID dead.
    """
    if os.name != "nt":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        ProcessCommandLineInformation = 60

        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR),
            ]

        h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_proc:
            return ""

        try:
            buf = ctypes.create_string_buffer(4096)
            ret_len = wintypes.ULONG(0)
            status = ntdll.NtQueryInformationProcess(
                h_proc, ProcessCommandLineInformation, buf, ctypes.sizeof(buf), ctypes.byref(ret_len)
            )
            if (status == 0xC0000004 or status == -1073741820) and ret_len.value > 0 and ret_len.value < 65536:
                buf = ctypes.create_string_buffer(ret_len.value)
                status = ntdll.NtQueryInformationProcess(
                    h_proc, ProcessCommandLineInformation, buf, ctypes.sizeof(buf), ctypes.byref(ret_len)
                )

            if status == 0:
                us = ctypes.cast(buf, ctypes.POINTER(UNICODE_STRING)).contents
                if us.Buffer and us.Length > 0:
                    return us.Buffer[:us.Length // 2]
            return ""
        finally:
            k32.CloseHandle(h_proc)
    except Exception:
        return ""


def _query_process_image_path(pid: int) -> str:
    """
    Safely retrieves the full executable disk path using QueryFullProcessImageNameW.
    Requires only PROCESS_QUERY_LIMITED_INFORMATION.
    """
    if os.name != "nt":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_proc:
            return ""
        try:
            buf = (ctypes.c_wchar * 1024)()
            size = wintypes.DWORD(1024)
            if k32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                return buf.value
            return ""
        finally:
            k32.CloseHandle(h_proc)
    except Exception:
        return ""


class BehavioralMonitor:
    """Continuously audits active Windows processes for anomalous behaviors and ransomware preparation."""

    def __init__(
        self,
        history_db: Optional[HistoryDatabase] = None,
        on_anomaly_detected: Optional[Callable[[Dict[str, Any]], None]] = None,
        poll_interval: float = 3.0,
    ):
        self.history_db = history_db or HistoryDatabase()
        self.on_anomaly_detected = on_anomaly_detected
        self.poll_interval = poll_interval

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._reported_anomalies: Set[str] = set()

    def start(self) -> bool:
        """Start the background behavioral monitoring thread."""
        if self.is_running:
            return True

        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="BI-BehavioralMonitor"
        )
        self._worker_thread.start()
        logger.info("Behavioral Process Monitor started.")
        return True

    def stop(self) -> None:
        """Stop background behavioral monitoring."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Behavioral Process Monitor stopped.")

    @staticmethod
    def get_process_snapshot() -> List[Dict[str, Any]]:
        """
        Query active Windows processes via native Toolhelp32 snapshot.
        Returns normalized list of process dictionaries with parent PID.
        """
        processes = []
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes

                class PROCESSENTRY32W(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", wintypes.LONG),
                        ("dwFlags", wintypes.DWORD),
                        ("szExeFile", wintypes.WCHAR * 260),
                    ]

                k32 = ctypes.windll.kernel32
                h_snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
                if h_snap and h_snap != -1:
                    entry = PROCESSENTRY32W()
                    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
                    if k32.Process32FirstW(h_snap, ctypes.byref(entry)):
                        while True:
                            pid = entry.th32ProcessID
                            cmdline = _query_process_cmdline(pid)
                            exec_path = _query_process_image_path(pid)
                            processes.append({
                                "name": entry.szExeFile.lower(),
                                "pid": str(pid),
                                "parent_pid": str(entry.th32ParentProcessID),
                                "memory": "",
                                "user": "",
                                "title": "",
                                "command_line": cmdline,
                                "executable_path": exec_path,
                            })
                            if not k32.Process32NextW(h_snap, ctypes.byref(entry)):
                                break
                    k32.CloseHandle(h_snap)
                return processes
            except Exception as e:
                logger.debug(f"Native Toolhelp32 snapshot error: {e}")

        # Fallback to tasklist if native query fails
        try:
            cmd = "tasklist /FO CSV /NH"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if not line or not line.startswith('"'):
                    continue
                cols = [c.strip('"') for c in line.split('","')]
                if len(cols) >= 2:
                    pname = cols[0]
                    pid = cols[1]
                    processes.append({
                        "name": pname.lower(),
                        "pid": pid,
                        "parent_pid": "",
                        "memory": "",
                        "user": "",
                        "title": "",
                        "command_line": "",
                    })
        except Exception as e:
            logger.debug(f"Process snapshot query error: {e}")

        return processes

    @classmethod
    def evaluate_process_behavior(cls, proc: Dict[str, Any], parent_name: str = "") -> Dict[str, Any]:
        """
        Evaluate a single process entry for behavioral anomalies, dropper patterns, and ransomware staging.
        """
        pname = proc.get("name", "").lower()
        cmdline = proc.get("command_line", "").lower()
        pid = proc.get("pid", "0")
        title = proc.get("title", "")
        parent = parent_name.lower()

        risk_score = 0
        indicators = []

        # 1. Anomalous Parent-Child Execution (e.g. Word -> PowerShell)
        if parent in ANOMALOUS_PARENTS and pname in SUSPICIOUS_CHILDREN:
            risk_score += 75
            indicators.append(f"AnomalousParentChild:{ANOMALOUS_PARENTS[parent]}->{pname}")

        # 2. Suspicious Command-Line Signatures
        target_text = f"{cmdline} {title}"
        for pattern_re, rule_id, weight in SUSPICIOUS_CLI_INDICATORS:
            if re.search(pattern_re, target_text):
                risk_score += weight
                indicators.append(rule_id)

        # 3. Execution from Temp or Public User Directories
        exec_path = proc.get("executable_path", "").lower()
        if exec_path:
            for s_dir in SUSPICIOUS_EXECUTION_DIRS:
                if s_dir in exec_path:
                    risk_score += 40
                    indicators.append(f"SuspiciousExecutionPath:{s_dir}")
                    break

        is_anomaly = risk_score >= 60
        severity = SEVERITY_CLEAN
        if risk_score >= 85:
            severity = SEVERITY_CRITICAL
        elif risk_score >= 60:
            severity = SEVERITY_HIGH
        elif risk_score >= 35:
            severity = SEVERITY_MEDIUM

        return {
            "pid": pid,
            "process_name": pname,
            "parent_name": parent,
            "is_anomaly": is_anomaly,
            "risk_score": min(risk_score, 100),
            "severity": severity,
            "indicators": indicators,
            "summary": f"Behavioral threat score {risk_score}/100. Flags: {', '.join(indicators[:2])}" if indicators else "Clean process behavior",
        }

    def _monitor_loop(self) -> None:
        """Periodic background evaluation loop."""
        while not self._stop_event.is_set():
            try:
                processes = self.get_process_snapshot()
                pid_map = {p["pid"]: p["name"] for p in processes}
                for proc in processes:
                    if self._stop_event.is_set():
                        break

                    parent_name = pid_map.get(proc.get("parent_pid"), "")
                    res = self.evaluate_process_behavior(proc, parent_name=parent_name)
                    if res["is_anomaly"]:
                        key = f"{res['pid']}-{res['process_name']}"
                        if key not in self._reported_anomalies:
                            self._reported_anomalies.add(key)
                            logger.warning(
                                f"BEHAVIORAL ANOMALY DETECTED: {res['process_name']} (PID: {res['pid']}) - {res['summary']}"
                            )

                            self.history_db.record_threat(
                                session_id="BEHAVIORAL-SENTINEL",
                                file_path=f"Process:{res['process_name']}[PID:{res['pid']}]",
                                file_hash="BEHAVIORAL_ANOMALY",
                                file_size=0,
                                threat_name=f"Behavioral.{res['indicators'][0] if res['indicators'] else 'Suspicious'}",
                                threat_family="Behavioral",
                                severity=res["severity"],
                                action_taken="ALERTED",
                                details=res["summary"],
                            )

                            if self.on_anomaly_detected:
                                try:
                                    self.on_anomaly_detected(res)
                                except Exception:
                                    pass

            except Exception as e:
                logger.debug(f"Error in behavioral monitor loop: {e}")

            self._stop_event.wait(self.poll_interval)

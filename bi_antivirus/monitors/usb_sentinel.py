"""
BI Antivirus - USB & Removable Media Sentinel
Automatically monitors and audits removable storage devices (USB flash drives, SD cards)
for autorun.inf worms, hidden malicious executables, and LNK shortcut hijacking.
Uses native Windows kernel32 APIs (GetLogicalDriveStrings, GetDriveType) without external drivers.
"""

import os
import sys
import time
import ctypes
import threading
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
)
from bi_antivirus.database.history import HistoryDatabase

logger = logging.getLogger("bi_antivirus.usb_sentinel")

# Windows Drive Type Constants
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6


class USBSentinel:
    """Monitors for removable drive attachments and scans drive roots for autorun worms and shortcut hijacking."""

    def __init__(
        self,
        history_db: Optional[HistoryDatabase] = None,
        on_drive_attached: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None,
        poll_interval: float = 3.0,
    ):
        self.history_db = history_db or HistoryDatabase()
        self.on_drive_attached = on_drive_attached
        self.on_threat_detected = on_threat_detected
        self.poll_interval = poll_interval

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._known_removable_drives: Set[str] = set()

    @staticmethod
    def get_removable_drives() -> List[str]:
        """
        Query system for currently mounted removable drives using kernel32.
        Returns list of root paths (e.g. ['E:\\', 'F:\\']).
        """
        if os.name != "nt":
            return []

        drives = []
        try:
            kernel32 = ctypes.windll.kernel32
            # Get buffer length needed
            buf_len = kernel32.GetLogicalDriveStringsW(0, None)
            if buf_len <= 0:
                return []

            buf = ctypes.create_unicode_buffer(buf_len)
            kernel32.GetLogicalDriveStringsW(buf_len, buf)

            # Drives are returned as null-delimited strings ending in double null
            raw_drives = buf.raw.decode("utf-16le").split("\x00")
            for drive in raw_drives:
                drive = drive.strip()
                if not drive:
                    continue
                d_type = kernel32.GetDriveTypeW(drive)
                if d_type == DRIVE_REMOVABLE:
                    drives.append(drive)
        except Exception as e:
            logger.debug(f"Failed querying removable drives: {e}")

        return drives

    @staticmethod
    def get_usb_hardware_devices() -> List[Dict[str, Any]]:
        """
        Extract genuine USB storage hardware metadata (Vendor, Product, Hardware ID, Serial)
        directly from the Windows Registry (HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR).
        Provides robust, non-admin read-only hardware discovery without WMI permissions issues.
        """
        if os.name != "nt":
            return []

        devices = []
        try:
            import winreg
            base_key = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as k_base:
                device_count = winreg.QueryInfoKey(k_base)[0]
                for i in range(device_count):
                    try:
                        dev_subkey = winreg.EnumKey(k_base, i)
                        with winreg.OpenKey(k_base, dev_subkey) as k_dev:
                            inst_count = winreg.QueryInfoKey(k_dev)[0]
                            for j in range(inst_count):
                                try:
                                    inst_subkey = winreg.EnumKey(k_dev, j)
                                    with winreg.OpenKey(k_dev, inst_subkey) as k_inst:
                                        friendly_name = ""
                                        hw_ids = []
                                        try:
                                            friendly_name, _ = winreg.QueryValueEx(k_inst, "FriendlyName")
                                        except Exception:
                                            friendly_name = dev_subkey.replace("Disk&Ven_", "").replace("&Prod_", " ")
                                        try:
                                            hw_ids, _ = winreg.QueryValueEx(k_inst, "HardwareID")
                                        except Exception:
                                            hw_ids = [dev_subkey]

                                        devices.append({
                                            "device_key": dev_subkey,
                                            "friendly_name": friendly_name,
                                            "serial_number": inst_subkey.split("&")[0],
                                            "hardware_id": hw_ids[0] if hw_ids else dev_subkey,
                                            "all_hardware_ids": list(hw_ids) if isinstance(hw_ids, (list, tuple)) else [str(hw_ids)],
                                        })
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"USBSTOR registry query notice: {e}")

        return devices

    @classmethod
    def audit_drive_root(cls, drive_path: str) -> Dict[str, Any]:
        """
        Scan a removable drive root for autorun.inf threats, shortcut worms, and hidden payloads.
        """
        root = Path(drive_path)
        threats_found = []
        is_threat = False
        risk_score = 0

        if not root.exists() or not root.is_dir():
            return {
                "drive": drive_path,
                "is_threat": False,
                "error": "Drive inaccessible or disconnected",
                "threats": [],
            }

        # 1. Check for autorun.inf
        autorun_file = root / "autorun.inf"
        if autorun_file.exists():
            try:
                content = autorun_file.read_text(encoding="utf-8", errors="ignore").lower()
                suspicious_keys = ["open=", "shellexecute=", "action=", "icon="]
                matched_keys = [k for k in suspicious_keys if k in content]
                if matched_keys:
                    is_threat = True
                    risk_score += 85
                    threats_found.append({
                        "file_path": str(autorun_file),
                        "threat_name": "Worm.Removable.AutorunExecution",
                        "severity": SEVERITY_CRITICAL,
                        "description": f"Malicious autorun.inf configured to execute binaries automatically upon insertion (Keys: {', '.join(matched_keys)}).",
                    })
            except Exception as e:
                logger.debug(f"Could not read autorun.inf on {drive_path}: {e}")

        # 2. Check for hidden executables and LNK shortcut worm patterns
        try:
            entries = list(root.iterdir())
            lnk_count = 0
            hidden_exe_count = 0

            for entry in entries:
                if entry.is_file():
                    ext = entry.suffix.lower()
                    if ext == ".lnk":
                        lnk_count += 1
                        # Inspect LNK raw bytes for embedded command interpreter payloads
                        try:
                            raw_b = entry.read_bytes()[:2048].lower()
                            if any(k in raw_b for k in (b"powershell", b"cmd.exe", b"mshta", b"certutil", b"wscript", b"cscript")):
                                is_threat = True
                                risk_score += 95
                                threats_found.append({
                                    "file_path": str(entry),
                                    "threat_name": "Worm.Removable.MaliciousLNKPayload",
                                    "severity": SEVERITY_CRITICAL,
                                    "description": f"Shortcut '{entry.name}' contains embedded command interpreter launch sequence.",
                                })
                        except Exception:
                            pass
                    elif ext in (".exe", ".scr", ".vbs", ".bat", ".cmd", ".pif"):
                        # Check if hidden
                        if entry.name.startswith("."):
                            hidden_exe_count += 1
                        elif os.name == "nt":
                            try:
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(entry))
                                if attrs != -1 and (attrs & 0x02):  # FILE_ATTRIBUTE_HIDDEN
                                    hidden_exe_count += 1
                            except Exception:
                                pass

                    # Check for BadUSB / Rubber Ducky keystroke injection scripts
                    name_l = entry.name.lower()
                    if name_l in ("inject.bin", "payload.dd", "ducky.txt") or name_l.endswith(".ducky"):
                        is_threat = True
                        risk_score += 90
                        threats_found.append({
                            "file_path": str(entry),
                            "threat_name": "Exploit.BadUSB.DuckyScriptPayload",
                            "severity": SEVERITY_CRITICAL,
                            "description": f"Removable media contains BadUSB / Rubber Ducky hardware payload '{entry.name}'.",
                        })
                    elif ext in (".txt", ".ini", ".cfg"):
                        try:
                            head = entry.read_text(encoding="utf-8", errors="ignore")[:300].upper()
                            if head.startswith("REM ") and any(k in head for k in ("DELAY ", "STRING ", "GUI R", "ENTER")):
                                is_threat = True
                                risk_score += 90
                                threats_found.append({
                                    "file_path": str(entry),
                                    "threat_name": "Exploit.BadUSB.DuckyScriptPayload",
                                    "severity": SEVERITY_CRITICAL,
                                    "description": f"Removable media file '{entry.name}' contains Rubber Ducky keystroke injection script.",
                                })
                        except Exception:
                            pass

            # Pattern: Shortcut worm replaces folders with .lnk files
            if lnk_count >= 3 and len(entries) > 0 and (lnk_count / len(entries)) > 0.4:
                is_threat = True
                risk_score += 75
                threats_found.append({
                    "file_path": str(root),
                    "threat_name": "Worm.Removable.ShortcutHijack",
                    "severity": SEVERITY_HIGH,
                    "description": f"Removable drive exhibits Shortcut Worm characteristics ({lnk_count} LNK redirection files detected).",
                })

            if hidden_exe_count > 0:
                is_threat = True
                risk_score += 80
                threats_found.append({
                    "file_path": str(root),
                    "threat_name": "Trojan.Removable.HiddenExecutable",
                    "severity": SEVERITY_HIGH,
                    "description": f"Detected {hidden_exe_count} hidden executable(s) placed directly on the root of the removable drive.",
                })

        except Exception as e:
            logger.debug(f"Error enumerating files on {drive_path}: {e}")

        return {
            "drive": drive_path,
            "is_threat": is_threat,
            "risk_score": min(risk_score, 100),
            "threats_count": len(threats_found),
            "threats": threats_found,
            "status": "THREAT_DETECTED" if is_threat else "CLEAN",
        }

    def start(self) -> bool:
        """Start background USB monitor thread."""
        if self.is_running:
            return True

        self._known_removable_drives = set(self.get_removable_drives())
        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="BI-USBSentinel"
        )
        self._worker_thread.start()
        logger.info(f"USB Sentinel started. Baseline removable drives: {self._known_removable_drives or 'None'}")
        return True

    def stop(self) -> None:
        """Stop background USB sentinel."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("USB Sentinel stopped.")

    def _monitor_loop(self) -> None:
        """Periodic loop checking for newly attached removable storage."""
        while not self._stop_event.is_set():
            try:
                current_drives = set(self.get_removable_drives())
                new_drives = current_drives - self._known_removable_drives

                for drive in new_drives:
                    logger.info(f"REMOVABLE STORAGE ATTACHED: {drive}. Initiating automated security audit...")
                    audit = self.audit_drive_root(drive)

                    if self.on_drive_attached:
                        try:
                            self.on_drive_attached(audit)
                        except Exception:
                            pass

                    if audit["is_threat"]:
                        logger.warning(f"THREATS FOUND ON USB DRIVE {drive}: {audit['threats_count']} threat(s) detected!")
                        for t in audit["threats"]:
                            self.history_db.record_threat(
                                session_id="USB-SENTINEL",
                                file_path=t.get("file_path", drive),
                                file_hash="USB_MEDIA_THREAT",
                                file_size=0,
                                threat_name=t.get("threat_name", "Worm.Removable.Generic"),
                                threat_family="Worm",
                                severity=t.get("severity", SEVERITY_HIGH),
                                action_taken="FLAGGED",
                                details=t.get("description", ""),
                            )
                            if self.on_threat_detected:
                                try:
                                    self.on_threat_detected(t)
                                except Exception:
                                    pass

                self._known_removable_drives = current_drives
            except Exception as e:
                logger.debug(f"USB Sentinel loop error: {e}")

            self._stop_event.wait(self.poll_interval)

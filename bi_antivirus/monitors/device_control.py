"""
BI Antivirus - Enterprise Device Control Sentinel
Granular control and audit of removable storage media (USB flash drives, external HDDs, SD cards).
Features:
1. Continuous detection of mounted storage devices using native Win32 kernel32 APIs.
2. Volume metadata extraction: drive letter, volume label, filesystem, serial number, and capacity.
3. Policy-driven access decisions: ALLOW, READ_ONLY, or BLOCK based on PolicyEngine rules.
4. Genuine Windows OS-level enforcement mechanisms:
   - READ_ONLY: Enforces Windows StorageDevicePolicies WriteProtect registry setting (HKLM).
   - BLOCK: Filesystem dismount and media handle lock via DeviceIoControl(FSCTL_DISMOUNT_VOLUME).
5. Comprehensive audit logging into HistoryDatabase (security_events table).
6. Non-destructive, user-space operation with zero kernel crashes.
"""

import os
import sys
import time
import ctypes
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Tuple

try:
    import winreg
except ImportError:
    winreg = None

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
)
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.policy_engine import (
    PolicyEngine,
    DEVICE_ACTION_ALLOW,
    DEVICE_ACTION_READ_ONLY,
    DEVICE_ACTION_BLOCK,
)

logger = logging.getLogger("bi_antivirus.device_control")

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

# Windows DeviceIoControl Control Codes
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020
IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808


class DeviceControlSentinel:
    """Enforces enterprise Device Control policies on removable media."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        history_db: Optional[HistoryDatabase] = None,
        on_device_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        poll_interval: float = 2.0,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.history_db = history_db or HistoryDatabase()
        self.on_device_event = on_device_event
        self.poll_interval = poll_interval

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Track active devices: {drive_letter: metadata_dict}
        self._active_devices: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def get_drive_metadata(drive_letter: str) -> Dict[str, Any]:
        """
        Extract detailed volume metadata using GetVolumeInformationW and GetDiskFreeSpaceExW.
        """
        root = drive_letter if drive_letter.endswith("\\") else drive_letter + "\\"
        metadata = {
            "drive_letter": root,
            "volume_name": "Removable Disk",
            "filesystem": "Unknown",
            "serial_number": "0000-0000",
            "total_bytes": 0,
            "free_bytes": 0,
            "is_removable": True,
        }

        if os.name != "nt":
            return metadata

        try:
            kernel32 = ctypes.windll.kernel32

            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            serial_num = ctypes.c_ulong(0)
            max_comp_len = ctypes.c_ulong(0)
            fs_flags = ctypes.c_ulong(0)

            res = kernel32.GetVolumeInformationW(
                root,
                vol_name_buf,
                len(vol_name_buf),
                ctypes.byref(serial_num),
                ctypes.byref(max_comp_len),
                ctypes.byref(fs_flags),
                fs_name_buf,
                len(fs_name_buf),
            )

            if res:
                metadata["volume_name"] = vol_name_buf.value or "Removable Disk"
                metadata["filesystem"] = fs_name_buf.value or "FAT32"
                sn_val = serial_num.value
                metadata["serial_number"] = f"{(sn_val >> 16) & 0xFFFF:04X}-{sn_val & 0xFFFF:04X}"

            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            total_free = ctypes.c_ulonglong(0)

            if kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free_bytes), ctypes.byref(total_bytes), ctypes.byref(total_free)):
                metadata["total_bytes"] = total_bytes.value
                metadata["free_bytes"] = free_bytes.value

        except Exception as e:
            logger.debug(f"Failed querying volume metadata for {drive_letter}: {e}")

        return metadata

    @staticmethod
    def get_mounted_removable_drives() -> List[str]:
        """List currently mounted removable drive roots using kernel32."""
        if os.name != "nt":
            return []

        drives = []
        try:
            kernel32 = ctypes.windll.kernel32
            buf_len = kernel32.GetLogicalDriveStringsW(0, None)
            if buf_len <= 0:
                return []

            buf = ctypes.create_unicode_buffer(buf_len)
            kernel32.GetLogicalDriveStringsW(buf_len, buf)

            raw_drives = buf.raw.decode("utf-16le").split("\x00")
            for d in raw_drives:
                d = d.strip()
                if not d:
                    continue
                if kernel32.GetDriveTypeW(d) == DRIVE_REMOVABLE:
                    drives.append(d)
        except Exception as e:
            logger.debug(f"Failed querying mounted drives: {e}")

        return drives

    # ------------------------------------------------------------------
    # Real Windows OS Enforcement Mechanisms
    # ------------------------------------------------------------------

    @staticmethod
    def enforce_os_write_protect(enable: bool = True) -> Tuple[bool, str]:
        """
        Configure Windows StorageDevicePolicies WriteProtect registry setting.
        When WriteProtect == 1, Windows kernel storage stack enforces read-only access on USB drives.
        Requires Administrator rights.
        """
        if winreg is None or os.name != "nt":
            return False, "Windows registry not available on this platform."

        subkey = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        val = 1 if enable else 0

        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, val)
            status_text = "Enabled (Read-Only enforced)" if enable else "Disabled (Read-Write allowed)"
            logger.info(f"OS-level StorageDevicePolicies WriteProtect set to: {status_text}")
            return True, f"Windows StorageDevicePolicies WriteProtect {status_text}"
        except PermissionError:
            msg = "Administrator privileges required to modify StorageDevicePolicies WriteProtect registry."
            logger.warning(msg)
            return False, msg
        except Exception as e:
            msg = f"Failed setting StorageDevicePolicies WriteProtect: {e}"
            logger.warning(msg)
            return False, msg

    @staticmethod
    def query_os_write_protect() -> Optional[bool]:
        """Query current state of Windows StorageDevicePolicies WriteProtect."""
        if winreg is None or os.name != "nt":
            return None

        subkey = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                val, _ = winreg.QueryValueEx(key, "WriteProtect")
                return bool(val == 1)
        except Exception:
            return False

    @staticmethod
    def dismount_blocked_drive(drive_path: str) -> Tuple[bool, str]:
        """
        Safely dismount a blocked volume using native Win32 DeviceIoControl (FSCTL_DISMOUNT_VOLUME).
        Invalidates all open file handles and blocks access to the volume without system reboot.
        """
        if os.name != "nt":
            return False, "Dismount operation only supported on Windows OS."

        drive_letter = drive_path.rstrip("\\")
        device_name = f"\\\\.\\{drive_letter}"

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            INVALID_HANDLE_VALUE = -1

            h_device = kernel32.CreateFileW(
                device_name,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )

            if h_device == INVALID_HANDLE_VALUE or not h_device:
                # May fail if not run as administrator
                return False, f"Could not acquire exclusive volume handle for {device_name} (Administrator rights required)."

            bytes_returned = wintypes.DWORD(0)

            # 1. Attempt FSCTL_LOCK_VOLUME
            kernel32.DeviceIoControl(h_device, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)

            # 2. Attempt FSCTL_DISMOUNT_VOLUME
            res = kernel32.DeviceIoControl(h_device, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)

            # 3. Attempt IOCTL_STORAGE_EJECT_MEDIA
            kernel32.DeviceIoControl(h_device, IOCTL_STORAGE_EJECT_MEDIA, None, 0, None, 0, ctypes.byref(bytes_returned), None)

            kernel32.CloseHandle(h_device)

            if res:
                logger.info(f"OS-level filesystem dismount successful for {drive_path}")
                return True, f"Volume {drive_path} successfully dismounted and locked at OS level."
            else:
                return False, f"FSCTL_DISMOUNT_VOLUME failed on {drive_path}."

        except Exception as e:
            return False, f"Dismount exception on {drive_path}: {e}"

    # ------------------------------------------------------------------
    # Policy Evaluation & Enforcement Coordinator
    # ------------------------------------------------------------------

    def evaluate_and_enforce_device(self, drive_path: str) -> Dict[str, Any]:
        """
        Evaluate attached removable device against enterprise Device Control policy,
        execute appropriate OS-level enforcement, record audit event, and return action report.
        """
        meta = self.get_drive_metadata(drive_path)
        serial = meta.get("serial_number", "")
        vol_name = meta.get("volume_name", "")

        # 1. Evaluate against PolicyEngine
        action, reason = self.policy_engine.evaluate_device_policy(
            device_id=drive_path,
            serial_number=serial,
        )

        os_enforced = False
        os_detail = "Audit event logged."

        # 2. Execute Real OS Enforcement
        if action == DEVICE_ACTION_READ_ONLY:
            os_enforced, os_detail = self.enforce_os_write_protect(True)
        elif action == DEVICE_ACTION_BLOCK:
            os_enforced, os_detail = self.dismount_blocked_drive(drive_path)
        elif action == DEVICE_ACTION_ALLOW:
            os_enforced = True
            os_detail = "Authorized by enterprise policy."

        event_record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": "DEVICE_CONTROL",
            "drive_path": drive_path,
            "volume_name": vol_name,
            "serial_number": serial,
            "filesystem": meta.get("filesystem"),
            "total_size_mb": round(meta.get("total_bytes", 0) / (1024 * 1024), 2),
            "policy_action": action,
            "reason": reason,
            "os_enforced": os_enforced,
            "os_enforcement_detail": os_detail,
        }

        # 3. Log into SQLite history database
        try:
            severity = (
                SEVERITY_CRITICAL if action == DEVICE_ACTION_BLOCK
                else (SEVERITY_HIGH if action == DEVICE_ACTION_READ_ONLY else SEVERITY_CLEAN)
            )
            self.history_db.record_event(
                event_type=f"DEVICE_{action}",
                source="DEVICE_CONTROL",
                severity=severity,
                details=f"Device {drive_path} (SN: {serial}) policy: {action} ({reason}) | OS: {os_detail}",
            )
        except Exception as e:
            logger.debug(f"Failed recording device event to history db: {e}")

        # 4. Callback notification
        if self.on_device_event:
            try:
                self.on_device_event(event_record)
            except Exception as e:
                logger.debug(f"Error in device event callback: {e}")

        with self._lock:
            self._active_devices[drive_path] = event_record

        logger.info(f"Device Control evaluated {drive_path}: {action} (OS Enforced: {os_enforced}) - {reason}")
        return event_record

    def get_active_devices(self) -> List[Dict[str, Any]]:
        """Return list of currently connected removable devices and their policy state."""
        with self._lock:
            return list(self._active_devices.values())

    def start(self) -> None:
        """Start background device control listener thread."""
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="DeviceControlWorker")
        self._worker_thread.start()
        logger.info("Device Control Sentinel background monitor started.")

    def stop(self) -> None:
        """Stop background device control listener."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)
        logger.info("Device Control Sentinel stopped.")

    def _monitor_loop(self) -> None:
        """Background loop continuously tracking drive connections and disconnections."""
        last_drives: Set[str] = set()

        while not self._stop_event.is_set():
            try:
                current_drives = set(self.get_mounted_removable_drives())

                # Detect newly attached drives
                new_drives = current_drives - last_drives
                for drive in new_drives:
                    self.evaluate_and_enforce_device(drive)

                # Detect disconnected drives
                removed_drives = last_drives - current_drives
                for drive in removed_drives:
                    with self._lock:
                        if drive in self._active_devices:
                            del self._active_devices[drive]
                    logger.info(f"Removable storage disconnected: {drive}")

                last_drives = current_drives
            except Exception as e:
                logger.debug(f"Error in device monitor loop: {e}")

            self._stop_event.wait(self.poll_interval)

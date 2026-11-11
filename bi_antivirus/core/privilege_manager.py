"""
BI Antivirus - Privilege & Enforcement Mode Manager
Audits active Windows process security token, identifies Administrator vs Standard User mode,
and provides transparent visibility into which security capabilities are in Full Enforcement
versus Audit-Only mode.
"""

import sys
import os
import ctypes
from typing import Dict, Any, List


def is_user_admin() -> bool:
    """Check if current process has elevated Administrator privileges on Windows."""
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0  # POSIX fallback
    except Exception:
        return False


class PrivilegeManager:
    """Manages and reports the operating privilege level and enforcement boundaries."""

    @staticmethod
    def get_enforcement_details() -> Dict[str, Any]:
        """
        Returns a structured assessment of current process privileges,
        enforcement mode, and specific feature capabilities / restrictions.
        """
        is_admin = is_user_admin()

        if is_admin:
            mode_title = "Administrator Mode — Full Enforcement"
            integrity_level = "High Integrity (Elevated Token)"
            enforcement_mode = "FULL_ENFORCEMENT"
            status_color = "#00d285"  # Green
            explanation = (
                "BI Antivirus is running with full administrative privileges. "
                "All host OS enforcement capabilities—including active Windows Firewall rule deployment, "
                "USB StorageDevicePolicies registry write-locking, BitLocker status inspection, "
                "and system process handle interrogation—are active and operating at full capacity."
            )
        else:
            mode_title = "Standard User Mode — Audit Only"
            integrity_level = "Medium Integrity (Standard User Token)"
            enforcement_mode = "AUDIT_ONLY"
            status_color = "#f5a623"  # Amber / Warning
            explanation = (
                "BI Antivirus is running as a standard user. Real-time file inspection, "
                "heuristic PE analysis, machine learning detection, ransomware decoy traps, "
                "Authenticode validation, and local quarantine vaulting are fully operational for user files. "
                "However, system-level registry modifications, Windows Firewall rule enforcement, "
                "and privileged process termination operate in Audit-Only mode due to Windows UAC constraints."
            )

        features = {
            "realtime_file_guard": {
                "name": "Real-Time On-Access Sentinel",
                "state": "ACTIVE",
                "enforcement": "Full" if is_admin else "User Scope (Audit/Alert)",
                "requires_elevation": False,
                "notes": "Monitors filesystem events and caches clean binary reputations.",
            },
            "heuristic_and_ml": {
                "name": "Heuristic PE & ML Classifier",
                "state": "ACTIVE",
                "enforcement": "Full",
                "requires_elevation": False,
                "notes": "12-feature structural vectorizer and Shannon entropy analysis.",
            },
            "quarantine_vault": {
                "name": "AES-256 Quarantine Vault",
                "state": "ACTIVE",
                "enforcement": "Full",
                "requires_elevation": False,
                "notes": "Encrypted isolation with directory traversal protections.",
            },
            "authenticode_verifier": {
                "name": "WinTrust Authenticode Signature Check",
                "state": "ACTIVE",
                "enforcement": "Full",
                "requires_elevation": False,
                "notes": "Native wintrust.dll verification of publisher certificates.",
            },
            "ransomware_honeypots": {
                "name": "Ransomware Decoy Honey-traps",
                "state": "ACTIVE",
                "enforcement": "Full",
                "requires_elevation": False,
                "notes": "Canary trap monitoring and burst entropy tracking.",
            },
            "firewall_orchestration": {
                "name": "Windows Defender Firewall Control",
                "state": "ACTIVE" if is_admin else "AUDIT_ONLY",
                "enforcement": "Full (netsh applied)" if is_admin else "Audit Only (Staged in Queue)",
                "requires_elevation": True,
                "notes": (
                    "Active deployment of netsh advfirewall rules requires Administrator elevation. "
                    "In Standard User mode, rules are validated and staged in memory/logs."
                ),
            },
            "usb_device_control": {
                "name": "USB StorageDevicePolicies Lock",
                "state": "ACTIVE" if is_admin else "AUDIT_ONLY",
                "enforcement": "Full (Registry Lock)" if is_admin else "Audit Only (Worm Purge Active)",
                "requires_elevation": True,
                "notes": (
                    "Setting HKLM StorageDevicePolicies WriteProtect requires Administrator privileges. "
                    "Autorun.inf and LNK shortcut worm detection remains active in user mode."
                ),
            },
            "bitlocker_management": {
                "name": "Full Disk Encryption Sentinel",
                "state": "ACTIVE" if is_admin else "AUDIT_ONLY",
                "enforcement": "Full (Live manage-bde)" if is_admin else "Audit Only (Parser Ready)",
                "requires_elevation": True,
                "notes": "Querying manage-bde.exe status requires elevated administrative access.",
            },
            "process_guard": {
                "name": "Process Privilege & Token Guard",
                "state": "ACTIVE" if is_admin else "SCOPED_AUDIT",
                "enforcement": "Full (System Tokens)" if is_admin else "User Process Scope",
                "requires_elevation": True,
                "notes": (
                    "Auditing system-level process tokens and terminating privileged processes "
                    "requires Administrator rights. User-owned process inspection is fully active."
                ),
            },
            "etw_telemetry": {
                "name": "Event Tracing for Windows (ETW) Probe",
                "state": "DIAGNOSTIC_PROBE",
                "enforcement": "Diagnostic (Session restricted)" if not is_admin else "Kernel Session Capable",
                "requires_elevation": True,
                "notes": "Starting real-time ETW trace sessions requires Administrator or Performance Log Users.",
            },
        }

        # Filter features that are restricted or in audit-only mode
        restricted = [
            {"id": fid, **finfo}
            for fid, finfo in features.items()
            if finfo["requires_elevation"] and not is_admin
        ]

        return {
            "is_admin": is_admin,
            "mode_title": mode_title,
            "integrity_level": integrity_level,
            "enforcement_mode": enforcement_mode,
            "status_color": status_color,
            "explanation": explanation,
            "features": features,
            "restricted_features": restricted,
            "restricted_count": len(restricted),
        }

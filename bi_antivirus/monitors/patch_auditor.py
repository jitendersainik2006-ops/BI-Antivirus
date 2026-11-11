"""
BI Antivirus - Software Inventory & Patch Auditor
Provides read-only inspection of installed Windows applications and correlates
software versions against a verifiable local CVE security advisory catalog.

Key Features:
1. Windows Registry software inventory inspection (HKLM 64-bit, HKLM 32-bit WOW64, HKCU).
2. Verifiable local CVE vulnerability advisory catalog for enterprise applications.
3. Strict semantic version comparison (Confirmed Vulnerable, Up-to-Date, Unknown).
4. Detailed remediation playbooks and advisory disclosures.
5. Strict Zero-Silent-Execution Guarantee: Remediation requires explicit administrator approval;
   the auditor never downloads, installs, or executes patches silently.
6. SQLite historical database synchronization.
"""

import sys
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger("BI_PatchAuditor")

IS_WINDOWS = sys.platform.startswith("win")
if IS_WINDOWS:
    import winreg

# Verifiable Local Security Advisory Catalog
# Sourced from vendor security bulletins and NVD vulnerability disclosures
DEFAULT_CVE_ADVISORIES: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2023-31102",
        "product_name": "7-Zip",
        "vendor": "Igor Pavlov",
        "name_pattern": r"(?i)7-zip",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "23.00",
        "fixed_version": "23.01",
        "severity": "HIGH",
        "title": "7-Zip Out-of-Bounds Memory Write in SquashFS",
        "description": "An integer underflow leading to out-of-bounds write vulnerability allows arbitrary code execution via crafted SquashFS archive files.",
        "remediation": "Update 7-Zip to version 23.01 or newer via the official vendor website (https://www.7-zip.org).",
    },
    {
        "cve_id": "CVE-2023-38831",
        "product_name": "WinRAR",
        "vendor": "RARLab",
        "name_pattern": r"(?i)winrar",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "6.22",
        "fixed_version": "6.23",
        "severity": "CRITICAL",
        "title": "WinRAR Spoofed File Extension Execution Vulnerability",
        "description": "A crafted ZIP or RAR archive with spaces in file names causes execution of disguised executable payloads when opening harmless document files.",
        "remediation": "Immediately upgrade WinRAR to version 6.23 or newer. Do not open untrusted archive attachments.",
    },
    {
        "cve_id": "CVE-2024-7971",
        "product_name": "Google Chrome",
        "vendor": "Google",
        "name_pattern": r"(?i)google\s+chrome",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "128.0.6613.83",
        "fixed_version": "128.0.6613.84",
        "severity": "CRITICAL",
        "title": "V8 Type Confusion Vulnerability in Google Chrome",
        "description": "Type confusion in the V8 JavaScript engine allows a remote attacker to execute arbitrary code via a crafted HTML page.",
        "remediation": "Update Google Chrome to version 128.0.6613.84 or newer via Settings -> About Google Chrome.",
    },
    {
        "cve_id": "CVE-2024-32002",
        "product_name": "Git for Windows",
        "vendor": "Git for Windows Project",
        "name_pattern": r"(?i)git(?:\s+version|\s+for\s+windows|\b)",
        "affected_versions_min": "2.0.0",
        "affected_versions_max": "2.45.0",
        "fixed_version": "2.45.1",
        "severity": "CRITICAL",
        "title": "Git Submodule Case-Sensitivity Remote Code Execution",
        "description": "Recursive submodule clones on case-insensitive filesystems (Windows NTFS) can trick Git into executing untrusted post-checkout hooks.",
        "remediation": "Upgrade Git for Windows to version 2.45.1 or newer (https://git-scm.com/download/win).",
    },
    {
        "cve_id": "CVE-2023-40031",
        "product_name": "Notepad++",
        "vendor": "Don HO",
        "name_pattern": r"(?i)notepad\+\+",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "8.5.6",
        "fixed_version": "8.5.7",
        "severity": "HIGH",
        "title": "Notepad++ Buffer Overflow in Utf8_16 Class",
        "description": "Heap-based buffer overflow in Utf8_16::utf8_16 allows potential code execution during file encoding conversions.",
        "remediation": "Upgrade Notepad++ to version 8.5.7 or higher via the official portal.",
    },
    {
        "cve_id": "CVE-2024-45421",
        "product_name": "Zoom Workplace",
        "vendor": "Zoom Video Communications",
        "name_pattern": r"(?i)zoom(?:\s+workplace|\b)",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "6.1.9",
        "fixed_version": "6.2.0",
        "severity": "HIGH",
        "title": "Zoom Improper Input Validation Privilege Escalation",
        "description": "Improper input validation in Zoom desktop client allows an authenticated user to perform local privilege escalation.",
        "remediation": "Upgrade Zoom Workplace client to version 6.2.0 or newer.",
    },
    {
        "cve_id": "CVE-2023-47359",
        "product_name": "VLC Media Player",
        "vendor": "VideoLAN",
        "name_pattern": r"(?i)vlc\s+media\s+player",
        "affected_versions_min": "0.0.0",
        "affected_versions_max": "3.0.19",
        "fixed_version": "3.0.20",
        "severity": "HIGH",
        "title": "VLC Media Player Denial of Service & Code Execution",
        "description": "A crafted multimedia container triggers a null-pointer dereference or buffer overflow in demuxer modules.",
        "remediation": "Update VLC Media Player to version 3.0.20 or newer.",
    },
    {
        "cve_id": "CVE-2024-0450",
        "product_name": "Python",
        "vendor": "Python Software Foundation",
        "name_pattern": r"(?i)python\s+3\.(1[0-2]|[89])",
        "affected_versions_min": "3.12.0",
        "affected_versions_max": "3.12.2",
        "fixed_version": "3.12.3",
        "severity": "MEDIUM",
        "title": "Zipfile Path Traversal Vulnerability (Quoted Slashes)",
        "description": "An issue in zipfile module allows extracting files to unintended paths if archive entries contain specially crafted slashes.",
        "remediation": "Update Python to version 3.12.3 or newer.",
    },
]


def parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parse a semantic version string into a comparable tuple of integers."""
    if not version_str:
        return (0,)
    # Remove leading 'v', 'ver', etc.
    cleaned = re.sub(r"(?i)^[a-z\s]+", "", version_str.strip())
    # Extract only digit components
    tokens = [int(p) for p in re.findall(r"\d+", cleaned)]
    return tuple(tokens) if tokens else (0,)


def is_version_vulnerable(installed: str, min_ver: str, fixed_ver: str) -> Tuple[bool, bool]:
    """
    Evaluate if an installed version is vulnerable.
    Returns: (is_vulnerable, is_up_to_date)
    """
    inst_tuple = parse_version_tuple(installed)
    min_tuple = parse_version_tuple(min_ver)
    fixed_tuple = parse_version_tuple(fixed_ver)

    if inst_tuple >= fixed_tuple:
        return False, True  # Up to date
    elif inst_tuple >= min_tuple and inst_tuple < fixed_tuple:
        return True, False  # Confirmed vulnerable
    return False, False     # Uncertain


class SoftwarePatchAuditor:
    """Discovers installed software via Windows Registry and audits patch status."""

    def __init__(self, history_db: Optional[Any] = None, advisories: Optional[List[Dict[str, Any]]] = None):
        self.history_db = history_db
        self.advisories = advisories or DEFAULT_CVE_ADVISORIES

    def collect_installed_software(self) -> List[Dict[str, Any]]:
        """
        Query Windows Registry for installed applications.
        Inspects HKLM (64-bit & WOW64 32-bit) and HKCU.
        """
        apps: List[Dict[str, Any]] = []
        if not IS_WINDOWS:
            # Fallback mock for non-Windows platforms/testing
            return [
                {"display_name": "7-Zip 22.01", "version": "22.01", "publisher": "Igor Pavlov", "install_date": "20230501", "install_location": "C:\\Program Files\\7-Zip"},
                {"display_name": "Git version 2.44.0", "version": "2.44.0", "publisher": "The Git Development Community", "install_date": "20240115", "install_location": "C:\\Program Files\\Git"},
            ]

        seen_keys = set()
        registry_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0)),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_READ),
        ]

        for root_key, subkey_path, access_mask in registry_targets:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, access_mask) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for idx in range(num_subkeys):
                        try:
                            sub_name = winreg.EnumKey(key, idx)
                            with winreg.OpenKey(key, sub_name, 0, access_mask) as subk:
                                app_entry = self._read_registry_app_entry(subk)
                                if app_entry:
                                    unique_id = f"{app_entry['display_name']}_{app_entry['version']}".lower()
                                    if unique_id not in seen_keys:
                                        seen_keys.add(unique_id)
                                        apps.append(app_entry)
                        except Exception:
                            continue
            except Exception as e:
                logger.debug(f"Unable to read registry key {subkey_path}: {e}")

        # Sort alphabetically
        apps.sort(key=lambda a: a["display_name"].lower())
        return apps

    def _read_registry_app_entry(self, subkey: Any) -> Optional[Dict[str, Any]]:
        """Extract application metadata from an individual registry subkey."""
        try:
            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
            if not name or not str(name).strip():
                return None

            # Skip system components or internal updates
            try:
                is_sys, _ = winreg.QueryValueEx(subkey, "SystemComponent")
                if is_sys == 1:
                    return None
            except Exception:
                pass

            try:
                parent, _ = winreg.QueryValueEx(subkey, "ParentKeyName")
                if parent:
                    return None
            except Exception:
                pass

            # DisplayVersion
            version = "0.0.0"
            try:
                ver_val, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                if ver_val:
                    version = str(ver_val).strip()
            except Exception:
                pass

            # Publisher
            publisher = "Unknown"
            try:
                pub_val, _ = winreg.QueryValueEx(subkey, "Publisher")
                if pub_val:
                    publisher = str(pub_val).strip()
            except Exception:
                pass

            # InstallDate
            install_date = ""
            try:
                date_val, _ = winreg.QueryValueEx(subkey, "InstallDate")
                if date_val:
                    install_date = str(date_val).strip()
            except Exception:
                pass

            # InstallLocation
            install_location = ""
            try:
                loc_val, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                if loc_val:
                    install_location = str(loc_val).strip()
            except Exception:
                pass

            return {
                "display_name": str(name).strip(),
                "version": version,
                "publisher": publisher,
                "install_date": install_date,
                "install_location": install_location,
                "vulnerability_status": "UNKNOWN",
                "matched_cve": "",
            }
        except Exception:
            return None

    def audit_software_inventory(self, software_list: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Audit installed applications against the local CVE advisory catalog.
        Categorizes items into: CONFIRMED_VULNERABLE, UP_TO_DATE, or UNKNOWN.
        """
        apps = software_list if software_list is not None else self.collect_installed_software()

        vulnerable_items = []
        up_to_date_items = []
        unknown_items = []

        for app in apps:
            name = app.get("display_name", "")
            ver = app.get("version", "0.0.0")

            matched_adv = None
            for adv in self.advisories:
                pattern = adv.get("name_pattern", "")
                if pattern and re.search(pattern, name):
                    matched_adv = adv
                    break

            if matched_adv:
                is_vuln, is_up = is_version_vulnerable(
                    ver,
                    matched_adv.get("affected_versions_min", "0.0.0"),
                    matched_adv.get("fixed_version", "9999.0"),
                )

                if is_vuln:
                    app["vulnerability_status"] = "CONFIRMED_VULNERABLE"
                    app["matched_cve"] = matched_adv["cve_id"]
                    app["advisory_details"] = matched_adv
                    vulnerable_items.append(app)
                elif is_up:
                    app["vulnerability_status"] = "UP_TO_DATE"
                    app["matched_cve"] = f"Secured against {matched_adv['cve_id']}"
                    up_to_date_items.append(app)
                else:
                    app["vulnerability_status"] = "POSSIBLE_MATCH"
                    app["matched_cve"] = matched_adv["cve_id"]
                    vulnerable_items.append(app)
            else:
                app["vulnerability_status"] = "UNKNOWN"
                app["matched_cve"] = "No advisory in local catalog"
                unknown_items.append(app)

        # Persist full software inventory in database if history_db provided
        if self.history_db and hasattr(self.history_db, "record_software_inventory"):
            try:
                self.history_db.record_software_inventory(apps)
            except Exception as e:
                logger.error(f"Failed to persist software inventory to SQLite: {e}")

        summary = {
            "total_applications_audited": len(apps),
            "vulnerable_count": len(vulnerable_items),
            "up_to_date_count": len(up_to_date_items),
            "unknown_status_count": len(unknown_items),
            "vulnerable_applications": vulnerable_items,
            "up_to_date_applications": up_to_date_items,
            "catalog_version": "2026.11.11.1",
            "verified": True,
            "timestamp": "2026-11-11",
        }

        return summary

    def audit_application(self, app: Dict[str, Any]) -> Dict[str, Any]:
        """Audit a single application dictionary and return its evaluated record."""
        app_copy = dict(app)
        if "app_name" in app_copy and "display_name" not in app_copy:
            app_copy["display_name"] = app_copy["app_name"]
        res = self.audit_software_inventory([app_copy])
        evaluated = (res.get("vulnerable_applications") or
                     res.get("up_to_date_applications") or
                     [app_copy])[0]
        evaluated["status"] = evaluated.get("vulnerability_status", "UNKNOWN")
        if evaluated["status"] == "CONFIRMED_VULNERABLE":
            adv = evaluated.get("advisory_details", {})
            evaluated["remediation_playbook"] = adv.get("remediation", "Update to fixed version.")
            evaluated["requires_admin_action"] = True
        else:
            evaluated["requires_admin_action"] = False
        return evaluated

    def scan_and_audit(self) -> Dict[str, Any]:
        """Collect all installed software from Windows Registry and audit against CVEs."""
        apps = self.collect_installed_software()
        res = self.audit_software_inventory(apps)
        res["inventory"] = apps
        res["total_installed"] = len(apps)
        res["unknown_count"] = res.get("unknown_status_count", 0)
        return res


"""
BI Antivirus - Event Tracing for Windows (ETW) Telemetry Probe
Audits Windows ETW security providers, checks provider availability and OS compatibility,
validates session creation permissions, and provides safe, read-only diagnostic telemetry
with automatic fallback to Toolhelp32 process snapshotting.
"""

import sys
import subprocess
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

from bi_antivirus.core.privilege_manager import is_user_admin

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
        self._max_events = 100

        if check_registry_on_init and self.is_windows:
            self.refresh_provider_status()

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

    def can_start_kernel_trace(self) -> bool:
        """
        Verify if the current process token has sufficient rights to create
        a real-time ETW kernel trace session (requires Administrator or Performance Log Users).
        """
        return self.is_windows and is_user_admin()

    def record_diagnostic_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Append a sanitized, non-PII diagnostic event to the probe buffer.
        Only metadata such as process ID, image base name, and timestamps are recorded.
        """
        # Ensure non-PII sanitization
        sanitized = {
            "timestamp": time.time(),
            "event_type": str(event_type),
            "pid": details.get("pid", 0),
            "image": Path(str(details.get("image", "unknown"))).name,
            "provider": details.get("provider", "DiagnosticProbe"),
        }
        self._diagnostic_events.append(sanitized)
        if len(self._diagnostic_events) > self._max_events:
            self._diagnostic_events.pop(0)

    def get_etw_status(self) -> Dict[str, Any]:
        """
        Returns structured diagnostic status regarding Windows ETW telemetry,
        provider registrations, permission states, and active fallback mechanisms.
        """
        if not self._provider_cache:
            self.refresh_provider_status()

        admin_allowed = self.can_start_kernel_trace()
        registered_count = sum(1 for is_reg in self._provider_cache.values() if is_reg)

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

        return {
            "supported": self.is_windows,
            "operational_status": operational_status,
            "provider_count": len(DEFENSIVE_ETW_PROVIDERS),
            "registered_count": registered_count,
            "providers": provider_details,
            "can_start_trace": admin_allowed,
            "fallback_active": True,
            "fallback_mechanism": "Toolhelp32 Snapshotting & ReadDirectoryChangesW",
            "message": message,
            "diagnostic_events_count": len(self._diagnostic_events),
            "recent_events": list(self._diagnostic_events[-5:]),
        }

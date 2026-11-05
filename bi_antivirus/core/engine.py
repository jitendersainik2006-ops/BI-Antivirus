"""
BI Antivirus - Master Antivirus Engine Coordinator
Unifies the 12 modular subsystems into an integrated cyber defense platform:
Scanner, Detection Engine, Quarantine Vault, Signature DB, History DB,
Real-Time Guard, Web Shield, Firewall Auditor, Scheduler, Updater, Logger,
Threat Event Dispatcher, Voice Sentinel, and Local REST API.
"""

import time
import uuid
import threading
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List, Tuple

from bi_antivirus.config import (
    load_settings,
    save_settings,
    SCAN_TYPE_QUICK,
    SCAN_TYPE_FULL,
    SCAN_TYPE_CUSTOM,
)
from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.core.scanner import FileScanner
from bi_antivirus.core.quarantine import QuarantineManager
from bi_antivirus.core.updater import UpdateManager
from bi_antivirus.core.scheduler import ScanScheduler
from bi_antivirus.core.logger import SecurityLogger
from bi_antivirus.monitors.realtime import RealTimeGuard
from bi_antivirus.monitors.web_protection import WebProtection
from bi_antivirus.monitors.firewall_monitor import FirewallMonitor
from bi_antivirus.monitors.voice_alert import voice_service, VoiceAlertService
from bi_antivirus.core.dispatcher import event_dispatcher, ThreatEventDispatcher
from bi_antivirus.api.server import LocalAPIServer


class AntivirusEngine:
    """Master controller orchestrating all protection components and security workflows."""

    def __init__(self):
        # 1. Database Managers
        self.sig_db = SignatureDatabase()
        self.history_db = HistoryDatabase()

        # 2. Security Logger
        self.sec_logger = SecurityLogger()

        # 3. Detection & Quarantine Core
        self.detector = ThreatDetector(signature_db=self.sig_db)
        self.quarantine_mgr = QuarantineManager()

        # 4. Scanner Engine
        self.scanner = FileScanner(detector=self.detector, history_db=self.history_db)

        # 5. Network & Web Protection
        self.web_shield = WebProtection(signature_db=self.sig_db)
        self.firewall_monitor = FirewallMonitor()

        # 6. Real-Time Guard
        self.realtime_guard = RealTimeGuard(
            detector=self.detector,
            quarantine_mgr=self.quarantine_mgr,
            history_db=self.history_db,
            on_threat_detected=self._on_realtime_threat,
        )

        # 7. Update Manager
        self.updater = UpdateManager(sig_db=self.sig_db)

        # 8. Automated Scheduler
        self.scheduler = ScanScheduler(on_trigger_scan=self._on_scheduled_scan_trigger)

        # 9. Voice Alert Sentinel
        self.voice: VoiceAlertService = voice_service

        # 10. Webhook & Automation Dispatcher
        self.dispatcher: ThreatEventDispatcher = event_dispatcher

        # 11. Loopback-Only Local REST API Server
        self.api_server = LocalAPIServer(self)

        # Live Status
        self.system_status = "PROTECTED"  # "PROTECTED", "SCANNING", "THREAT_DETECTED", "WARNING"
        self.active_scan_thread: Optional[threading.Thread] = None

        # Callbacks for UI updates
        self.on_status_changed: Optional[Callable[[str], None]] = None
        self.on_threat_found: Optional[Callable[[Dict[str, Any]], None]] = None

    def initialize(self) -> None:
        """Initialize and start background protection services."""
        settings = load_settings()
        self.sec_logger.log_event("INFO", "ENGINE", "BI Antivirus Engine initialized on D: drive.")

        # Start Real-Time Guard
        if settings.get("realtime_protection_enabled", True):
            self.realtime_guard.start()
            self.sec_logger.log_event("INFO", "REALTIME", "Real-Time Protection Guard started.")

        # Start Automated Scheduler
        self.scheduler.start()
        self.sec_logger.log_event("INFO", "SCHEDULER", "Scan Scheduler started.")

        # Start Event Dispatcher
        self.dispatcher.start()

        # Start Local REST API Server (Loopback only 127.0.0.1:8765)
        if settings.get("api_enabled", True):
            self.api_server.start()

        self._update_system_status()

    def shutdown(self) -> None:
        """Gracefully stop background protection tasks."""
        self.api_server.stop()
        self.dispatcher.stop()
        self.realtime_guard.stop()
        self.scheduler.stop()
        if self.scanner.is_scanning:
            self.scanner.cancel_scan()
        self.sec_logger.log_event("INFO", "ENGINE", "BI Antivirus Engine stopped gracefully.")

    def _update_system_status(self) -> None:
        """Recalculate overall protection badge."""
        if self.scanner.is_scanning:
            self.system_status = "SCANNING"
        elif self.scanner.threats_found:
            self.system_status = "THREAT_DETECTED"
        elif not self.realtime_guard.is_running:
            self.system_status = "WARNING"
        else:
            self.system_status = "PROTECTED"

        if self.on_status_changed:
            try:
                self.on_status_changed(self.system_status)
            except Exception:
                pass

    def _on_realtime_threat(self, threat: Dict[str, Any]) -> None:
        """Handle threat intercepted by real-time guard."""
        self.system_status = "THREAT_DETECTED"
        self.sec_logger.log_event(
            "ALERT",
            "REALTIME_GUARD",
            f"Threat detected: {threat.get('threat_name')} at {threat.get('file_path')}",
            details=threat,
        )

        # Dispatch sanitized event to local automation & voice
        self.dispatcher.emit_threat_event(threat, scan_id="REALTIME_GUARD")

        if self.on_threat_found:
            try:
                self.on_threat_found(threat)
            except Exception:
                pass
        self._update_system_status()

    def _on_scheduled_scan_trigger(self, scan_type: str) -> None:
        """Triggered when scheduler activates a recurring scan."""
        self.sec_logger.log_event("INFO", "SCHEDULER", f"Scheduled scan triggered: {scan_type}")
        if not self.scanner.is_scanning:
            if scan_type == SCAN_TYPE_FULL:
                self.start_full_scan()
            else:
                self.start_quick_scan()

    # Scanning API
    def start_quick_scan(self, progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None) -> str:
        """Start Quick Scan in dedicated background worker thread."""
        if self.scanner.is_scanning:
            return self.scanner.current_session_id

        session_id = f"SCAN-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
        self.scanner.current_session_id = session_id

        def _worker():
            self._update_system_status()
            self.sec_logger.log_event("INFO", "SCANNER", f"Quick Scan started ({session_id}).")
            res = self.scanner.scan_quick(progress_cb=progress_cb)
            self._update_system_status()
            self.sec_logger.log_event(
                "INFO",
                "SCANNER",
                f"Quick Scan completed. Files: {res['files_scanned']}, Threats: {res['threats_count']}",
            )

            # Emit events for threats discovered
            for t in res.get("threats", []):
                self.dispatcher.emit_threat_event(t, scan_id=res["session_id"])

            # Voice announcement
            self.voice.announce_scan_completed(res["files_scanned"], res["threats_count"])

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-QuickScanThread")
        self.active_scan_thread.start()
        return session_id

    def start_full_scan(self, progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        """Start Full Scan in background thread."""
        if self.scanner.is_scanning:
            return

        def _worker():
            self._update_system_status()
            self.sec_logger.log_event("INFO", "SCANNER", "Full Scan started.")
            res = self.scanner.scan_full(progress_cb=progress_cb)
            self._update_system_status()
            self.sec_logger.log_event(
                "INFO",
                "SCANNER",
                f"Full Scan completed. Files: {res['files_scanned']}, Threats: {res['threats_count']}",
            )

            for t in res.get("threats", []):
                self.dispatcher.emit_threat_event(t, scan_id=res["session_id"])

            self.voice.announce_scan_completed(res["files_scanned"], res["threats_count"])

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-FullScanThread")
        self.active_scan_thread.start()

    def start_custom_scan(
        self, target_path: Path, progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> None:
        """Start Custom Folder/File Scan in background thread."""
        if self.scanner.is_scanning:
            return

        def _worker():
            self._update_system_status()
            self.sec_logger.log_event("INFO", "SCANNER", f"Custom Scan started on target: {target_path}")
            res = self.scanner.scan_path(target_path, progress_cb=progress_cb)
            self._update_system_status()
            self.sec_logger.log_event(
                "INFO",
                "SCANNER",
                f"Custom Scan completed. Files: {res['files_scanned']}, Threats: {res['threats_count']}",
            )

            for t in res.get("threats", []):
                self.dispatcher.emit_threat_event(t, scan_id=res["session_id"])

            self.voice.announce_scan_completed(res["files_scanned"], res["threats_count"])

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-CustomScanThread")
        self.active_scan_thread.start()

    def cancel_scan(self) -> None:
        """Cancel currently active scan."""
        if self.scanner.is_scanning:
            self.scanner.cancel_scan()
            self.sec_logger.log_event("WARN", "SCANNER", "Scan cancellation requested by user.")

    # Quarantine Management API
    def quarantine_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Safely quarantine a detected threat."""
        file_path = Path(threat["file_path"])
        res = self.quarantine_mgr.quarantine_file(file_path, threat)
        if res.get("success"):
            self.sec_logger.log_event(
                "ALERT",
                "QUARANTINE",
                f"Quarantined {threat.get('threat_name')} from {file_path} to vault {res.get('quarantine_id')}",
            )
            # Update threat record in history if available
            history_recs = self.history_db.get_threat_history(limit=5)
            for rec in history_recs:
                if rec["file_path"] == str(file_path):
                    self.history_db.update_threat_action(rec["id"], "QUARANTINED")
                    break
        self._update_system_status()
        return res

    def restore_threat(self, quarantine_id: str, custom_target: Optional[Path] = None) -> Tuple[bool, str]:
        """Safely restore a quarantined file."""
        ok, msg = self.quarantine_mgr.restore_file(quarantine_id, custom_target)
        if ok:
            self.sec_logger.log_event("INFO", "QUARANTINE", f"Restored {quarantine_id}: {msg}")
        return ok, msg

    def purge_quarantined_threat(self, quarantine_id: str) -> Tuple[bool, str]:
        """Safely delete quarantined file permanently (upon explicit user confirmation)."""
        ok, msg = self.quarantine_mgr.purge_file(quarantine_id)
        if ok:
            self.sec_logger.log_event("INFO", "QUARANTINE", f"Purged {quarantine_id} from vault.")
        return ok, msg

    # Reports & Diagnostics API
    def generate_security_report(self) -> Path:
        """Create structured Markdown assessment report on D: drive."""
        scan_summary = {
            "session_id": self.scanner.current_session_id,
            "scan_type": self.scanner.scan_type,
            "files_scanned": self.scanner.files_scanned,
            "duration_seconds": round(self.scanner.end_time - self.scanner.start_time, 2) if self.scanner.end_time else 0,
            "threats_count": len(self.scanner.threats_found),
            "threats": self.scanner.threats_found,
            "status": "COMPLETED",
        }
        db_stats = self.sig_db.get_stats()
        quarantine_items = self.quarantine_mgr.list_quarantine()
        fw_status = self.firewall_monitor.get_firewall_profiles_status()

        report_path = self.sec_logger.generate_security_report(
            scan_summary=scan_summary,
            db_stats=db_stats,
            quarantine_items=quarantine_items,
            firewall_status=fw_status,
        )
        self.sec_logger.log_event("INFO", "REPORTS", f"Generated security report: {report_path.name}")
        return report_path

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Returns comprehensive status dictionary for dashboard cards."""
        db_stats = self.sig_db.get_stats()
        hist_stats = self.history_db.get_aggregate_stats()
        quarantine_items = self.quarantine_mgr.list_quarantine()
        upd_status = self.updater.check_definition_status()
        settings = load_settings()

        return {
            "status": self.system_status,
            "is_scanning": self.scanner.is_scanning,
            "realtime_active": self.realtime_guard.is_running,
            "total_signatures": db_stats.get("total_indicators", 0),
            "definition_version": upd_status.get("version", "Current"),
            "definitions_up_to_date": upd_status.get("status") == "UP_TO_DATE",
            "total_files_scanned": hist_stats.get("total_files_scanned", 0),
            "total_threats_found": hist_stats.get("total_threats_found", 0),
            "quarantined_items_count": len(quarantine_items),
            "last_scan_time": hist_stats.get("last_scan_time", "Never"),
            "active_threats_in_session": len(self.scanner.threats_found),
            "api_server_active": self.api_server.is_running,
            "api_port": self.api_server.port,
            "voice_alerts_active": settings.get("voice_alerts_enabled", True),
            "voice_engine": settings.get("voice_engine", "SAPI"),
            "webhook_enabled": settings.get("webhook_enabled", False),
            "webhook_url": settings.get("webhook_url", "http://127.0.0.1:5678/webhook/bi-threat-alert"),
            "recent_dispatches": self.dispatcher.dispatched_history,
        }

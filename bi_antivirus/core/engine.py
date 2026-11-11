"""
BI Antivirus - Master Antivirus Engine Coordinator
Unifies the complete multi-layer cyber defense platform:
Scanner, Detection Engine, Quarantine Vault, Signature DB, History DB,
Real-Time Guard, Behavioral Monitor, Ransomware Shield, USB Sentinel,
Vulnerability Auditor, Web Shield, Firewall Auditor, Scheduler, Updater, Logger,
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
from bi_antivirus.core.vulnerability import VulnerabilityAuditor
from bi_antivirus.monitors.realtime import RealTimeGuard
from bi_antivirus.monitors.behavioral import BehavioralMonitor
from bi_antivirus.monitors.ransomware_shield import RansomwareShield
from bi_antivirus.monitors.usb_sentinel import USBSentinel
from bi_antivirus.monitors.web_protection import WebProtection
from bi_antivirus.monitors.firewall_monitor import FirewallMonitor
from bi_antivirus.monitors.voice_alert import voice_service, VoiceAlertService
from bi_antivirus.core.dispatcher import event_dispatcher, ThreatEventDispatcher
from bi_antivirus.api.server import LocalAPIServer
from bi_antivirus.core.policy_engine import PolicyEngine
from bi_antivirus.monitors.device_control import DeviceControlSentinel
from bi_antivirus.monitors.app_control import ApplicationControlSentinel
from bi_antivirus.monitors.encryption_manager import DiskEncryptionSentinel
from bi_antivirus.monitors.exploit_shield import MemoryExploitShield
from bi_antivirus.core.incident_graph import IncidentGraphEngine
from bi_antivirus.core.pe_classifier import PEClassifier
from bi_antivirus.monitors.patch_auditor import SoftwarePatchAuditor
from bi_antivirus.core.threat_intel import ThreatIntelEngine
from bi_antivirus.enterprise.fleet_manager import FleetManager
from bi_antivirus.enterprise.compliance_reporter import ComplianceReporter
from bi_antivirus.core.ml_engine import LocalMLEngine
from bi_antivirus.monitors.process_guard import ProcessGuard
from bi_antivirus.core.edr_engine import EDREngine
from bi_antivirus.enterprise.cloud_sandbox import CloudSandboxClient
from bi_antivirus.enterprise.rbac_manager import RBACManager
from bi_antivirus.enterprise.siem_exporter import SIEMExporter
from bi_antivirus.core.privilege_manager import PrivilegeManager, is_user_admin
from bi_antivirus.monitors.etw_telemetry import ETWTelemetryProbe


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

        # 6. Real-Time Filesystem Guard
        self.realtime_guard = RealTimeGuard(
            detector=self.detector,
            quarantine_mgr=self.quarantine_mgr,
            history_db=self.history_db,
            on_threat_detected=self._on_realtime_threat,
        )

        # 7. Behavioral Process Sentinel
        self.behavioral_monitor = BehavioralMonitor(
            history_db=self.history_db,
            on_anomaly_detected=self._on_behavioral_threat,
        )

        # 8. Advanced Ransomware Shield & Canary Decoys
        self.ransomware_shield = RansomwareShield(
            history_db=self.history_db,
            on_ransomware_alert=self._on_ransomware_threat,
        )

        # 9. USB & Removable Media Sentinel
        self.usb_sentinel = USBSentinel(
            history_db=self.history_db,
            on_threat_detected=self._on_usb_threat,
        )

        # 10. Vulnerability Auditor
        self.vulnerability_auditor = VulnerabilityAuditor

        # 11. Update Manager
        self.updater = UpdateManager(sig_db=self.sig_db)

        # 12. Automated Scheduler
        self.scheduler = ScanScheduler(on_trigger_scan=self._on_scheduled_scan_trigger)

        # 13. Voice Alert Sentinel
        self.voice: VoiceAlertService = voice_service

        # 14. Webhook & Automation Dispatcher
        self.dispatcher: ThreatEventDispatcher = event_dispatcher

        # 15. Loopback-Only Local REST API Server
        self.api_server = LocalAPIServer(self)

        # 16. Centralized Enterprise Policy Engine
        self.policy_engine = PolicyEngine()

        # 17. Enterprise Device Control Sentinel
        self.device_control = DeviceControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
            on_device_event=self._on_device_control_event,
        )

        # 18. Enterprise Application Control Sentinel
        self.app_control = ApplicationControlSentinel(
            policy_engine=self.policy_engine,
            history_db=self.history_db,
            on_violation=self._on_app_control_violation,
        )

        # 19. Full Disk Encryption (BitLocker) Sentinel
        self.encryption_sentinel = DiskEncryptionSentinel(
            history_db=self.history_db,
            on_compliance_alert=self._on_encryption_alert,
        )

        # 20. Enterprise EDR Incident Graph Engine
        self.incident_graph = IncidentGraphEngine(history_db=self.history_db)

        # 21. Defensive Memory Exploit Shield
        self.exploit_shield = MemoryExploitShield(
            history_db=self.history_db,
            on_exploit_threat=self._on_exploit_threat,
        )

        # 22. Local PE Static Feature Classifier
        self.pe_classifier = PEClassifier(history_db=self.history_db)

        # 23. Software Inventory & Patch Auditor
        self.patch_auditor = SoftwarePatchAuditor(history_db=self.history_db)

        # 24. Threat Intelligence Update Engine
        self.threat_intel = ThreatIntelEngine(history_db=self.history_db, sig_db=self.sig_db)

        # 25. Enterprise Fleet Management & Compliance Reporting
        self.fleet_manager = FleetManager()
        self.compliance_reporter = ComplianceReporter(fleet_manager=self.fleet_manager, history_db=self.history_db)

        # 26. Local ML Static PE Classification Engine
        self.ml_engine = LocalMLEngine()

        # 27. Process Protection Guard & Privilege Sentinel
        self.process_guard = ProcessGuard(history_db=self.history_db)

        # 28. Advanced Enterprise EDR Telemetry & Correlation Engine
        self.edr_engine = EDREngine(history_db=self.history_db)

        # 29. Cloud Sandbox Abstraction & Local Detonation Provider
        self.cloud_sandbox = CloudSandboxClient()

        # 30. Role-Based Access Control (RBAC) & Session Manager
        self.rbac_manager = RBACManager()

        # 31. SIEM Exporter & Cryptographic Hash Chaining Sentinel
        self.siem_exporter = SIEMExporter()

        # 32. Privilege & Enforcement Mode Manager
        self.privilege_manager = PrivilegeManager()

        # 33. Event Tracing for Windows (ETW) Telemetry Probe
        self.etw_probe = ETWTelemetryProbe(check_registry_on_init=False)

        # Live Status
        self.system_status = "PROTECTED"
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

        # Start Behavioral Sentinel
        self.behavioral_monitor.start()
        self.sec_logger.log_event("INFO", "BEHAVIORAL", "Behavioral Process Monitor started.")

        # Start Ransomware Shield
        self.ransomware_shield.start()
        self.sec_logger.log_event("INFO", "RANSOMWARE", "Ransomware Shield & Canaries active.")

        # Start USB Sentinel
        self.usb_sentinel.start()
        self.sec_logger.log_event("INFO", "USB_SENTINEL", "USB Removable Media Sentinel started.")

        # Start Enterprise Device Control Sentinel
        self.device_control.start()
        self.sec_logger.log_event("INFO", "DEVICE_CONTROL", "Enterprise Device Control Sentinel started.")

        # Start Full Disk Encryption Sentinel
        self.encryption_sentinel.start()
        self.sec_logger.log_event("INFO", "ENCRYPTION_SENTINEL", "Full Disk Encryption Sentinel started.")

        # Start Defensive Memory Exploit Shield
        self.exploit_shield.start()
        self.sec_logger.log_event("INFO", "EXPLOIT_SHIELD", "Defensive Memory Exploit Shield active.")

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
        self.behavioral_monitor.stop()
        self.ransomware_shield.stop()
        self.usb_sentinel.stop()
        self.device_control.stop()
        self.encryption_sentinel.stop()
        self.exploit_shield.stop()
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

        self.dispatcher.emit_threat_event(threat, scan_id="REALTIME_GUARD")
        try:
            self.incident_graph.ingest_event("THREAT_DETECTED", threat)
        except Exception as ig_err:
            self.sec_logger.log_event("WARNING", "EDR_GRAPH", f"Incident correlation error: {ig_err}")

        if self.on_threat_found:
            try:
                self.on_threat_found(threat)
            except Exception:
                pass
        self._update_system_status()

    def _on_behavioral_threat(self, anomaly: Dict[str, Any]) -> None:
        """Handle anomaly flagged by behavioral process monitor."""
        self.system_status = "THREAT_DETECTED"
        self.sec_logger.log_event(
            "ALERT",
            "BEHAVIORAL",
            f"Behavioral anomaly: {anomaly.get('process_name')} (PID: {anomaly.get('pid')})",
            details=anomaly,
        )

        threat_dict = {
            "file_path": f"Process:{anomaly.get('process_name')}",
            "threat_name": f"Behavioral.{anomaly.get('indicators', ['Suspicious'])[0]}",
            "severity": anomaly.get("severity", "HIGH"),
            "file_hash": "BEHAVIORAL_ANOMALY",
            "description": anomaly.get("summary", ""),
        }
        self.dispatcher.emit_threat_event(threat_dict, scan_id="BEHAVIORAL")
        try:
            self.incident_graph.ingest_event("PROCESS_SPAWN", anomaly)
        except Exception as ig_err:
            self.sec_logger.log_event("WARNING", "EDR_GRAPH", f"Incident correlation error: {ig_err}")

        if self.on_threat_found:
            try:
                self.on_threat_found(threat_dict)
            except Exception:
                pass
        self._update_system_status()

    def _on_ransomware_threat(self, alert_data: Dict[str, Any]) -> None:
        """Handle alert from Ransomware Shield."""
        self.system_status = "THREAT_DETECTED"
        self.sec_logger.log_event(
            "CRITICAL",
            "RANSOMWARE_SHIELD",
            f"Ransomware activity intercepted: {alert_data.get('summary')}",
            details=alert_data,
        )

        threat_dict = {
            "file_path": alert_data.get("file_path", "RANSOMWARE_TARGET"),
            "threat_name": alert_data.get("threat_name", "Ransomware.Attack"),
            "severity": alert_data.get("severity", "CRITICAL"),
            "file_hash": "RANSOMWARE_DETECTION",
            "description": alert_data.get("summary", ""),
        }
        self.dispatcher.emit_threat_event(threat_dict, scan_id="RANSOMWARE_SHIELD")
        try:
            self.incident_graph.ingest_event("RANSOMWARE_ALERT", alert_data)
        except Exception as ig_err:
            self.sec_logger.log_event("WARNING", "EDR_GRAPH", f"Incident correlation error: {ig_err}")

        if self.on_threat_found:
            try:
                self.on_threat_found(threat_dict)
            except Exception:
                pass
        self._update_system_status()

    def _on_usb_threat(self, threat: Dict[str, Any]) -> None:
        """Handle threat found on removable media."""
        self.system_status = "THREAT_DETECTED"
        self.sec_logger.log_event(
            "ALERT",
            "USB_SENTINEL",
            f"Removable media threat: {threat.get('threat_name')} at {threat.get('file_path')}",
            details=threat,
        )

        self.dispatcher.emit_threat_event(threat, scan_id="USB_SENTINEL")
        try:
            self.incident_graph.ingest_event("USB_DEVICE_EVENT", threat)
        except Exception as ig_err:
            self.sec_logger.log_event("WARNING", "EDR_GRAPH", f"Incident correlation error: {ig_err}")

        if self.on_threat_found:
            try:
                self.on_threat_found(threat)
            except Exception:
                pass
        self._update_system_status()

    def _on_device_control_event(self, event: Dict[str, Any]) -> None:
        """Handle policy decision from Enterprise Device Control Sentinel."""
        action = event.get("policy_action", "ALLOW")
        if action == "BLOCK":
            self.system_status = "THREAT_DETECTED"
            threat_dict = {
                "file_path": f"Device:{event.get('drive_path')}",
                "threat_name": "DeviceControl.BlockedStorageAttached",
                "severity": "CRITICAL",
                "file_hash": event.get("serial_number", "DEVICE_BLOCKED"),
                "description": f"Blocked unauthorized removable storage (Serial: {event.get('serial_number')}): {event.get('reason')}",
            }
            self.sec_logger.log_event("ALERT", "DEVICE_CONTROL", f"Blocked device: {event.get('drive_path')}", details=event)
            self.dispatcher.emit_threat_event(threat_dict, scan_id="DEVICE_CONTROL")
            try:
                self.incident_graph.ingest_event("USB_DEVICE_EVENT", {
                    "drive_letter": event.get("drive_path"),
                    "action": action,
                    "threat_found": True,
                })
            except Exception:
                pass
            if self.on_threat_found:
                try:
                    self.on_threat_found(threat_dict)
                except Exception:
                    pass
            self._update_system_status()
        elif action == "READ_ONLY":
            self.sec_logger.log_event("WARNING", "DEVICE_CONTROL", f"Device restricted to Read-Only: {event.get('drive_path')}", details=event)
        else:
            self.sec_logger.log_event("INFO", "DEVICE_CONTROL", f"Device authorized: {event.get('drive_path')}", details=event)

    def _on_app_control_violation(self, violation: Dict[str, Any]) -> None:
        """Handle violation from Enterprise Application Control Sentinel."""
        status = violation.get("status", "AUDIT")
        severity = "CRITICAL" if status == "BLOCK" else "HIGH"
        if status == "BLOCK":
            self.system_status = "THREAT_DETECTED"
        threat_dict = {
            "file_path": violation.get("file_path", "UNKNOWN_APPLICATION"),
            "threat_name": f"AppControl.{status}.Violation",
            "severity": severity,
            "file_hash": violation.get("sha256", "APP_CONTROL_HASH"),
            "description": f"Application Control policy triggered on {violation.get('file_name')}: {violation.get('reason')}",
        }
        self.sec_logger.log_event("ALERT", "APP_CONTROL", f"Application policy violation: {violation.get('file_name')} [{status}]", details=violation)
        self.dispatcher.emit_threat_event(threat_dict, scan_id="APPLICATION_CONTROL")
        try:
            self.incident_graph.ingest_event("APP_CONTROL_VIOLATION", {
                "path": violation.get("file_path"),
                "hash": violation.get("sha256"),
                "decision": violation.get("status"),
                "reason": violation.get("reason"),
            })
        except Exception:
            pass
        if self.on_threat_found and status == "BLOCK":
            try:
                self.on_threat_found(threat_dict)
            except Exception:
                pass
        self._update_system_status()

    def _on_exploit_threat(self, audit: Dict[str, Any]) -> None:
        """Handle high-risk exploit/RWX memory detection from Exploit Shield."""
        self.system_status = "THREAT_DETECTED"
        threat_dict = {
            "file_path": f"PID:{audit.get('pid')}:{audit.get('process_name')}",
            "threat_name": f"ExploitShield.{audit.get('risk_level')}.MemoryAnomaly",
            "severity": audit.get("risk_level", "HIGH"),
            "file_hash": f"PID_{audit.get('pid')}",
            "description": "; ".join(audit.get("findings", [])),
        }
        self.sec_logger.log_event("ALERT", "EXPLOIT_SHIELD", f"Memory threat flagged: {audit.get('process_name')} (PID: {audit.get('pid')})", details=audit)
        self.dispatcher.emit_threat_event(threat_dict, scan_id="EXPLOIT_SHIELD")
        try:
            self.incident_graph.ingest_event("MEMORY_EXPLOIT_ALERT", audit)
        except Exception as ig_err:
            self.sec_logger.log_event("WARNING", "EDR_GRAPH", f"Incident correlation error: {ig_err}")
        if self.on_threat_found:
            try:
                self.on_threat_found(threat_dict)
            except Exception:
                pass
        self._update_system_status()

    def _on_encryption_alert(self, alert_data: Dict[str, Any]) -> None:
        """Handle non-compliance warning from Disk Encryption Sentinel."""
        self.sec_logger.log_event(
            "WARNING",
            "DISK_ENCRYPTION",
            f"Drive encryption alert: {alert_data.get('details')}",
            details=alert_data,
        )

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
            try:
                self._update_system_status()
                self.sec_logger.log_event("INFO", "SCANNER", f"Quick Scan started ({session_id}).")
                res = self.scanner.scan_quick(progress_cb=progress_cb)
                self._update_system_status()
                self.sec_logger.log_event(
                    "INFO",
                    "SCANNER",
                    f"Quick Scan completed. Files: {res['files_scanned']}, Threats: {res['threats_count']}",
                )

                for t in res.get("threats", []):
                    self.dispatcher.emit_threat_event(t, scan_id=res["session_id"])

                self.voice.announce_scan_completed(res["files_scanned"], res["threats_count"])
            except Exception as e:
                self.sec_logger.log_event("ERROR", "SCANNER", f"Quick Scan error: {e}")
                self._update_system_status()

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-QuickScanThread")
        self.active_scan_thread.start()
        return session_id

    def start_full_scan(self, progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None) -> str:
        """Start Full System Scan in dedicated background thread."""
        if self.scanner.is_scanning:
            return self.scanner.current_session_id

        session_id = f"SCAN-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
        self.scanner.current_session_id = session_id

        def _worker():
            try:
                self._update_system_status()
                self.sec_logger.log_event("INFO", "SCANNER", f"Full Scan started ({session_id}).")
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
            except Exception as e:
                self.sec_logger.log_event("ERROR", "SCANNER", f"Full Scan error: {e}")
                self._update_system_status()

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-FullScanThread")
        self.active_scan_thread.start()
        return session_id

    def start_custom_scan(
        self,
        target_path: Path,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> str:
        """Start Custom Path Scan."""
        if self.scanner.is_scanning:
            return self.scanner.current_session_id

        session_id = f"SCAN-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
        self.scanner.current_session_id = session_id

        def _worker():
            try:
                self._update_system_status()
                self.sec_logger.log_event("INFO", "SCANNER", f"Custom Scan started on {target_path} ({session_id}).")
                res = self.scanner.scan_custom(target_path, progress_cb=progress_cb)
                self._update_system_status()
                self.sec_logger.log_event(
                    "INFO",
                    "SCANNER",
                    f"Custom Scan completed. Files: {res['files_scanned']}, Threats: {res['threats_count']}",
                )

                for t in res.get("threats", []):
                    self.dispatcher.emit_threat_event(t, scan_id=res["session_id"])

                self.voice.announce_scan_completed(res["files_scanned"], res["threats_count"])
            except Exception as e:
                self.sec_logger.log_event("ERROR", "SCANNER", f"Custom Scan error: {e}")
                self._update_system_status()

        self.active_scan_thread = threading.Thread(target=_worker, daemon=True, name="BI-CustomScanThread")
        self.active_scan_thread.start()
        return session_id

    def stop_scan(self) -> None:
        """Cancel the ongoing scan."""
        if self.scanner.is_scanning:
            self.scanner.cancel_scan()
            self.sec_logger.log_event("WARNING", "SCANNER", "Active scan cancelled by user.")
            self._update_system_status()

    def run_vulnerability_audit(self) -> Dict[str, Any]:
        """Execute on-demand system vulnerability assessment."""
        report = self.vulnerability_auditor.run_full_vulnerability_audit()
        self.sec_logger.log_event(
            "INFO",
            "VULNERABILITY",
            f"Vulnerability audit completed: Score {report['posture_score']}/100 ({report['posture_rating']}), {report['vulnerabilities_found']} issue(s).",
        )
        return report

    def generate_current_report(self) -> Path:
        """Compile and write comprehensive Markdown security assessment report on D: drive."""
        scan_summary = {
            "session_id": self.scanner.current_session_id or "ON-DEMAND-ASSESSMENT",
            "scan_type": self.scanner.scan_type,
            "files_scanned": self.scanner.files_scanned,
            "threats_count": len(self.scanner.threats_found),
            "threats": self.scanner.threats_found,
            "status": "COMPLETED",
        }
        db_stats = self.sig_db.get_stats()
        quarantine_items = self.quarantine_mgr.list_quarantine()
        fw_status = self.firewall_monitor.get_firewall_profiles_status()

        vuln_report = self.run_vulnerability_audit()
        report_path = self.sec_logger.generate_security_report(
            scan_summary=scan_summary,
            db_stats=db_stats,
            quarantine_items=quarantine_items,
            firewall_status=fw_status,
            vulnerability_report=vuln_report,
        )
        self.sec_logger.log_event("INFO", "REPORTS", f"Generated security report: {report_path.name}")
        return report_path

    generate_security_report = generate_current_report

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
            "behavioral_active": self.behavioral_monitor.is_running,
            "ransomware_shield_active": self.ransomware_shield.is_running,
            "usb_sentinel_active": self.usb_sentinel.is_running,
            "canaries_deployed": len(self.ransomware_shield.canaries),
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
            "enforcement_details": self.privilege_manager.get_enforcement_details(),
            "etw_status": self.etw_probe.get_etw_status(),
        }

    def quarantine_threat(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coordinates quarantine isolation of a detected threat.
        Moves file to encrypted vault, updates history, and dispatches security event.
        """
        file_path_raw = threat_info.get("file_path")
        if not file_path_raw:
            return {"success": False, "error": "No file path specified for quarantine"}
        file_path = Path(file_path_raw)
        res = self.quarantine_mgr.quarantine_file(file_path, threat_info)
        if res.get("success"):
            self.sec_logger.log_event(
                "INFO",
                "QUARANTINE",
                f"Threat isolated to encrypted vault: {file_path.name} (QID: {res.get('quarantine_id')})",
                details=res,
            )
            # Remove threat from active session scanner list if present
            self.scanner.threats_found = [
                t for t in self.scanner.threats_found if t.get("file_path") != str(file_path)
            ]
            self._update_system_status()
        return res

    def restore_threat(
        self,
        quarantine_id: str,
        custom_target: Optional[Path] = None,
        overwrite: bool = False,
    ) -> Tuple[bool, str]:
        """
        Restores a quarantined threat back to original location or custom target path.
        """
        ok, msg = self.quarantine_mgr.restore_file(
            quarantine_id,
            custom_target_path=custom_target,
            overwrite=overwrite,
        )
        if ok:
            self.sec_logger.log_event(
                "INFO",
                "QUARANTINE",
                f"Quarantined file restored: {quarantine_id}",
                details={"quarantine_id": quarantine_id, "message": msg},
            )
            self._update_system_status()
        return ok, msg

    def purge_threat(self, quarantine_id: str) -> Tuple[bool, str]:
        """
        Permanently purges a quarantined file from the vault.
        """
        ok, msg = self.quarantine_mgr.purge_file(quarantine_id)
        if ok:
            self.sec_logger.log_event(
                "INFO",
                "QUARANTINE",
                f"Quarantined file permanently purged: {quarantine_id}",
            )
            self._update_system_status()
        return ok, msg

    def inspect_pe_file(self, file_path: Path) -> Dict[str, Any]:
        """Runs explainable static feature inspection on a Portable Executable binary."""
        report = self.pe_classifier.analyze_file(file_path)
        self.sec_logger.log_event(
            "INFO" if report.get("verdict") == "BENIGN_PROBABLE" else "WARNING",
            "PE_CLASSIFIER",
            f"PE inspection complete for {Path(file_path).name}: {report.get('verdict')} (Score: {report.get('suspicion_score')})",
            details=report,
        )
        return report

    def audit_software_patches(self) -> Dict[str, Any]:
        """Discovers installed software and compares versions against local CVE advisories."""
        report = self.patch_auditor.scan_and_audit()
        self.sec_logger.log_event(
            "WARNING" if report.get("vulnerable_count", 0) > 0 else "INFO",
            "PATCH_AUDITOR",
            f"Software patch audit complete: {report.get('total_installed', 0)} installed, {report.get('vulnerable_count', 0)} vulnerable",
            details=report,
        )
        return report

    def apply_threat_intel_bundle(self, bundle_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validates and applies signed threat intelligence updates."""
        res = self.threat_intel.verify_and_apply_bundle(bundle_data)
        self.sec_logger.log_event(
            "INFO" if res.get("status") == "SUCCESS" else "ERROR",
            "THREAT_INTEL",
            f"Threat intel bundle update: {res.get('status')} - {res.get('message')}",
            details=res,
        )
        return res



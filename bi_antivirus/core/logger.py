"""
BI Antivirus - Structured Audit Logger & Security Report Generator
Maintains audit logs of security events and compiles formal Markdown assessment reports on D: drive.
Strictly non-destructive and privacy-focused: keeps all telemetry local.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from bi_antivirus.config import (
    EVENT_LOG_PATH,
    REPORTS_DIR,
    APP_NAME,
    APP_VERSION,
    ENGINE_VERSION,
)

logger = logging.getLogger("bi_antivirus.logger")


class SecurityLogger:
    """Handles structured event logging to bi_security.log and generates Markdown reports."""

    def __init__(self, log_path: Optional[Path] = None, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 3):
        self.log_path = Path(log_path or EVENT_LOG_PATH)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backup_count = backup_count

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max_bytes to bound disk usage."""
        if not self.log_path.exists():
            return
        try:
            if self.log_path.stat().st_size >= self.max_bytes:
                for i in range(self.backup_count - 1, 0, -1):
                    sfn = self.log_path.with_name(f"{self.log_path.name}.{i}")
                    dfn = self.log_path.with_name(f"{self.log_path.name}.{i + 1}")
                    if sfn.exists():
                        if dfn.exists():
                            dfn.unlink()
                        sfn.rename(dfn)
                dfn = self.log_path.with_name(f"{self.log_path.name}.1")
                if dfn.exists():
                    dfn.unlink()
                self.log_path.rename(dfn)
        except Exception as e:
            logger.debug(f"Log rotation exception: {e}")

    def log_event(self, level: str, source: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Record a structured security event entry to the audit log.
        Format: [TIMESTAMP] [LEVEL] [SOURCE] Message | JSON_DETAILS
        """
        self._rotate_if_needed()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level.upper()}] [{source.upper()}] {message}"
        if details:
            try:
                entry += f" | {json.dumps(details)}"
            except Exception:
                pass
        entry += "\n"

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Failed to append to security log: {e}")

    def read_recent_events(self, max_lines: int = 50) -> List[str]:
        """Fetch the most recent audit log entries for display in dashboard."""
        if not self.log_path.exists():
            return []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                return [line.strip() for line in lines[-max_lines:]]
        except Exception:
            return []

    @staticmethod
    def generate_security_report(
        scan_summary: Optional[Dict[str, Any]] = None,
        db_stats: Optional[Dict[str, Any]] = None,
        quarantine_items: Optional[List[Dict[str, Any]]] = None,
        firewall_status: Optional[Dict[str, Any]] = None,
        vulnerability_report: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Produce a comprehensive, timestamped Markdown Security Report in reports/ directory.
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        now_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file = REPORTS_DIR / f"security_report_{now_str}.md"

        quarantine_count = len(quarantine_items or [])
        scan = scan_summary or {}
        sigs = db_stats or {}
        fw = firewall_status or {}
        vuln = vulnerability_report or {}

        content = f"""# {APP_NAME} Security Assessment Report
**Platform:** {APP_NAME} {APP_VERSION} (Engine: {ENGINE_VERSION})  
**Generated At:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Storage Location:** `{REPORTS_DIR}` (D: Drive)  

---

## 1. Executive Protection Summary
- **Overall Protection Status:** {"SECURE / OPERATIONAL" if not scan.get("threats_count") else "THREATS RESOLVED / FLAGGED"}
- **Signature Definitions Active:** {sigs.get("total_indicators", "Active")}
- **Database Version:** {sigs.get("version", "Current")}
- **Files Quarantined in Vault:** {quarantine_count}
- **Windows Firewall Active:** {fw.get("all_active", "Audited")}
- **System Posture Score:** {vuln.get("posture_score", "N/A")}/100 ({vuln.get("posture_rating", "Audited")})

---

## 2. Latest Scan Metrics
- **Scan Type:** {scan.get("scan_type", "Ad-Hoc / On-Demand")}
- **Session ID:** `{scan.get("session_id", "N/A")}`
- **Files Inspected:** {scan.get("files_scanned", 0)}
- **Duration:** {scan.get("duration_seconds", 0)} seconds
- **Threats Identified:** {scan.get("threats_count", 0)}
- **Scan Status:** {scan.get("status", "COMPLETED")}

"""

        if scan.get("threats"):
            content += "### Detected Threats Breakdown\n\n"
            content += "| Threat Name | Family | Severity | Target Path | Risk Score |\n"
            content += "|-------------|--------|----------|-------------|------------|\n"
            for t in scan["threats"]:
                content += f"| `{t.get('threat_name')}` | {t.get('threat_family')} | **{t.get('severity')}** | `{t.get('file_path')}` | {t.get('risk_score', 0)}/100 |\n"
            content += "\n"
        else:
            content += "> [!NOTE]\n> No active threats were discovered during the scanned file range.\n\n"

        content += f"""---

## 3. Quarantine Vault Inventory
- Total Quarantined Artifacts: **{quarantine_count}**
"""
        if quarantine_items:
            content += "\n| Quarantine ID | Original Filename | Identified Threat | Severity | Quarantined At |\n"
            content += "|---------------|-------------------|-------------------|----------|----------------|\n"
            for q in quarantine_items[:10]:
                content += f"| `{q.get('quarantine_id')}` | {q.get('file_name')} | `{q.get('threat_name')}` | {q.get('severity')} | {q.get('quarantined_at')} |\n"
        else:
            content += "\n*Vault is currently clean with 0 isolated items.*\n"

        content += f"""
---

## 4. Passive Firewall & Network Audit
- Domain Profile: **{fw.get('Domain', 'N/A')}**
- Private Profile: **{fw.get('Private', 'N/A')}**
- Public Profile: **{fw.get('Public', 'N/A')}**
- *Safety Notice: Windows Defender Firewall and Windows Defender are strictly monitored and preserved.*
"""

        if vuln.get("checks"):
            content += f"""
---

## 5. System Vulnerability & Posture Assessment
- Security Posture Score: **{vuln.get('posture_score', 100)}/100** ({vuln.get('posture_rating', 'GOOD')})
- Checks Passed: **{vuln.get('passed_checks', 0)} / {vuln.get('total_checks', 0)}**

| Security Control | Result | Status | Recommendation |
|------------------|--------|--------|----------------|
"""
            for chk in vuln["checks"]:
                content += f"| {chk['check']} | {chk['value']} | **{chk['status']}** | {chk['recommendation']} |\n"

        content += f"""
---

## 6. Security Recommendations
1. Ensure Real-Time Guard and Behavioral Monitor remain activated.
2. Regularly execute the scheduled Daily Quick Scan.
3. Review quarantined files and approve restoration only for confirmed internal files.
4. Keep definitions updated using the integrated Update Manager.
5. Address any high-priority vulnerability audit findings.

*Report produced by {APP_NAME} Black Intel Security Engine.*
"""
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(content)

        return report_file

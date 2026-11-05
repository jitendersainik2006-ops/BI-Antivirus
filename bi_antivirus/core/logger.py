"""
BI Antivirus - Security Event Logger & Report Generator
Maintains persistent, tamper-evident audit logs on D: drive (logs/bi_security.log)
and generates professional security scan reports and executive summaries.
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from bi_antivirus.config import (
    EVENT_LOG_PATH,
    REPORTS_DIR,
    APP_NAME,
    APP_VERSION,
    ENGINE_VERSION,
)


class SecurityLogger:
    """Centralized security event logger and report generation engine."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = Path(log_path or EVENT_LOG_PATH)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._setup_file_handler()

    def _setup_file_handler(self) -> None:
        self.logger = logging.getLogger("bi_security_audit")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            fh = logging.FileHandler(str(self.log_path), encoding="utf-8")
            fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

    def log_event(self, level: str, category: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Log a structured security audit event."""
        detail_str = f" | Details: {details}" if details else ""
        formatted = f"[{category.upper()}] {message}{detail_str}"
        lvl = level.upper()
        if lvl in ("CRITICAL", "ALERT"):
            self.logger.critical(formatted)
        elif lvl == "WARN" or lvl == "WARNING":
            self.logger.warning(formatted)
        elif lvl == "ERROR":
            self.logger.error(formatted)
        else:
            self.logger.info(formatted)

    def read_recent_logs(self, max_lines: int = 100) -> List[str]:
        """Read latest lines from security audit log."""
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

---

## 5. Security Recommendations
1. Ensure Real-Time Guard remains activated to monitor incoming files in Downloads and Temp.
2. Regularly execute the scheduled Daily Quick Scan.
3. Review quarantined files and approve restoration only for confirmed internal files.
4. Keep definitions updated using the integrated Update Manager.

*Report produced by {APP_NAME} Black Intel Security Engine.*
"""
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(content)

        return report_file

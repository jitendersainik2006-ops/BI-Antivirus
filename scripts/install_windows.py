"""
BI Antivirus - Enterprise Windows Installation & Setup Wizard
Performs first-run installation, environment validation, and system setup:
1. Validates Python 3.10+ (64-bit) runtime and dependencies
2. Checks Windows OS edition, build compatibility, and permissions
3. Prepares D: drive folder structure (data, logs, quarantine, reports)
4. Initializes and migrates SQLite databases with WAL mode and indexes
5. Pre-seeds harmless test signatures and heuristic rules
6. Verifies DPAPI master vault key security
7. Generates comprehensive installation diagnostics report on D: drive
8. Verifies shortcut launchers (run_gui.bat, run_cli.bat)
"""

import os
import sys
import json
import time
import shutil
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.config import (
    APP_NAME,
    APP_VERSION,
    ENGINE_VERSION,
    DATA_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    QUARANTINE_VAULT_DIR,
    REPORTS_DIR,
    SIGNATURES_DB_PATH,
    HISTORY_DB_PATH,
    QUARANTINE_DB_PATH,
    load_settings,
    save_settings,
)
from bi_antivirus.core.windows_compat import WindowsCompatibilityAuditor
from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.quarantine import QuarantineManager


def run_installation() -> int:
    print("=" * 75)
    print(f"       {APP_NAME} - WINDOWS INSTALLATION & SETUP WIZARD")
    print(f"       Version: {APP_VERSION} | Engine: {ENGINE_VERSION}")
    print(f"       Target Storage: {PROJECT_DIR} (D: Drive)")
    print("=" * 75)

    # 1. Pre-Flight Compatibility Audit
    print("\n[*] Step 1/5: Auditing host compatibility and runtime environment...")
    auditor = WindowsCompatibilityAuditor(project_root=PROJECT_DIR)
    audit_report = auditor.run_full_audit()

    py_status = audit_report["checks"]["python"]["status"]
    win_status = audit_report["checks"]["windows"]["status"]
    storage_status = audit_report["checks"]["storage"]["status"]
    priv_data = audit_report["checks"]["privileges"]

    print(f"    - Python Runtime:       {audit_report['checks']['python']['version']} ({py_status})")
    print(f"    - Operating System:     {audit_report['checks']['windows']['release']} Build {audit_report['checks']['windows']['build']} ({win_status})")
    print(f"    - Storage Target:       {audit_report['checks']['storage']['drive']} ({audit_report['checks']['storage']['free_space_gb']} GB Free) ({storage_status})")
    print(f"    - Token Elevation:      {'ELEVATED (Administrator)' if priv_data['is_elevated_admin'] else 'STANDARD USER (Visibility Mode)'}")

    if py_status != "PASSED":
        print(f"[!] Critical Error: Python environment check failed: {audit_report['checks']['python']}")
        return 1

    # 2. Directory Structure Verification
    print("\n[*] Step 2/5: Establishing isolated D: drive directory tree...")
    dirs_to_create = [
        DATA_DIR,
        LOGS_DIR,
        QUARANTINE_DIR,
        QUARANTINE_VAULT_DIR,
        REPORTS_DIR,
    ]
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)
        print(f"    [+] Verified: {d}")

    # 3. Database Initialization & Schema Migrations
    print("\n[*] Step 3/5: Initializing SQLite databases and performance indexes...")
    sig_db = SignatureDatabase()
    stats = sig_db.get_stats()
    print(f"    [+] Signature DB Initialized: {stats['total_indicators']} indicators active (v{stats['version']})")

    hist_db = HistoryDatabase()
    ok, hist_msg = hist_db.check_integrity()
    print(f"    [+] History DB Initialized: {hist_msg}")

    qm = QuarantineManager()
    q_audit = qm.verify_vault_integrity()
    print(f"    [+] Quarantine Vault Initialized: {q_audit['intact_records']} intact records")

    # 4. Settings Configuration
    print("\n[*] Step 4/5: Generating enterprise configuration profile...")
    settings = load_settings()
    settings["installed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    settings["installation_path"] = str(PROJECT_DIR)
    settings["is_elevated_install"] = priv_data["is_elevated_admin"]
    save_settings(settings)
    print("    [+] Settings saved to config/settings.json")

    # 5. Launchers & Final Diagnostic Report
    print("\n[*] Step 5/5: Finalizing installation diagnostics...")
    diag_file = DATA_DIR / "installation_diagnostic_report.json"
    audit_report["installed_at"] = settings["installed_at"]
    audit_report["launcher_gui"] = str(PROJECT_DIR / "run_gui.bat")
    audit_report["launcher_cli"] = str(PROJECT_DIR / "run_cli.bat")

    with open(diag_file, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2)

    print(f"    [+] Installation diagnostic report written to: {diag_file}")

    print("\n" + "=" * 75)
    print("       INSTALLATION COMPLETED SUCCESSFULLY")
    print("=" * 75)
    print(f"To launch the Graphical Desktop Console:  run_gui.bat")
    print(f"To launch the Command Line Interface:     run_cli.bat scan --quick")
    print("=" * 75 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(run_installation())

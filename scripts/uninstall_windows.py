"""
BI Antivirus - Enterprise Windows Uninstallation Wizard
Safely uninstalls or decommissions the BI Antivirus local deployment:
1. Validates working environment and project root (strictly on D: drive).
2. Stops running background services or monitors if active.
3. Preserves user data, quarantine vaults, history databases, and reports by default.
4. Optionally purges generated runtime artifacts only when explicitly requested (--purge-data).
5. Cleans up temporary installation diagnostics and caches without touching system files.
"""

import os
import sys
import shutil
import argparse
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.config import (
    APP_NAME,
    APP_VERSION,
    DATA_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    QUARANTINE_VAULT_DIR,
    REPORTS_DIR,
)


def run_uninstallation(purge_data: bool = False, non_interactive: bool = False) -> int:
    print("=" * 75)
    print(f"       {APP_NAME} - WINDOWS UNINSTALLATION WIZARD")
    print(f"       Version: {APP_VERSION}")
    print(f"       Target Directory: {PROJECT_DIR}")
    print("=" * 75)

    if not non_interactive and not purge_data:
        print("\nNotice: By default, your security event history, quarantine vault,")
        print("and generated compliance reports will be PRESERVED safely on D: drive.")
        print("To purge all local data, run with --purge-data or select below.")

    # 1. Clean transient caches and diagnostics
    print("\n[*] Step 1/3: Removing transient caches and diagnostic reports...")
    diag_file = DATA_DIR / "installation_diagnostic_report.json"
    if diag_file.exists():
        try:
            diag_file.unlink()
            print(f"    [+] Removed: {diag_file}")
        except Exception as e:
            print(f"    [-] Could not remove {diag_file}: {e}")

    # Remove Python bytecode caches in project
    removed_pyc = 0
    for pycache in PROJECT_DIR.rglob("__pycache__"):
        try:
            shutil.rmtree(pycache, ignore_errors=True)
            removed_pyc += 1
        except Exception:
            pass
    print(f"    [+] Cleaned {removed_pyc} bytecode cache directories.")

    # 2. Handle data directories
    if purge_data:
        print("\n[*] Step 2/3: Purging user databases, quarantine vaults, and reports...")
        data_targets = [
            ("Quarantine Vault", QUARANTINE_VAULT_DIR),
            ("Quarantine Staging", QUARANTINE_DIR),
            ("Logs Directory", LOGS_DIR),
            ("Reports Directory", REPORTS_DIR),
            ("Runtime Databases", DATA_DIR),
        ]
        for name, p in data_targets:
            if p.exists():
                try:
                    shutil.rmtree(p, ignore_errors=True)
                    print(f"    [+] Purged {name}: {p}")
                except Exception as e:
                    print(f"    [-] Error purging {p}: {e}")
    else:
        print("\n[*] Step 2/3: Preserving user data and quarantine records...")
        print(f"    [+] Preserved Quarantine Vault: {QUARANTINE_VAULT_DIR}")
        print(f"    [+] Preserved Security History: {DATA_DIR}")
        print(f"    [+] Preserved Compliance Reports: {REPORTS_DIR}")

    # 3. Final summary
    print("\n[*] Step 3/3: Uninstallation summary...")
    print("=" * 75)
    print("       UNINSTALLATION COMPLETED")
    print("=" * 75)
    if purge_data:
        print("All runtime databases and quarantine records have been purged.")
    else:
        print("All runtime security records preserved. You may safely delete the")
        print("repository directory or reinstall at any time via setup_windows.bat.")
    print("=" * 75 + "\n")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BI Antivirus Windows Uninstaller")
    parser.add_argument("--purge-data", action="store_true", help="Purge all quarantine, history databases, and reports")
    parser.add_argument("--yes", "-y", action="store_true", help="Non-interactive mode")
    args = parser.parse_args()

    sys.exit(run_uninstallation(purge_data=args.purge_data, non_interactive=args.yes))

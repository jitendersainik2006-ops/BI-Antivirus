"""
BI Antivirus - Primary Application Entry Point
Starts the modern dark-themed Desktop Dashboard GUI by default,
or routes to the Command Line Interface (CLI) if arguments are supplied.
"""

import sys
import os
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.config import APP_NAME, APP_VERSION
from bi_antivirus.core.recovery_manager import CrashRecoveryManager


def main():
    # Automated crash detection, startup recovery & single-instance locking
    recovery_mgr = CrashRecoveryManager()
    recovery_report = recovery_mgr.perform_startup_recovery()
    recovery_mgr.register_shutdown_hooks()

    if recovery_report.get("previous_unclean_shutdown"):
        print("[*] Crash Recovery: Recovered from previous unexpected termination.")

    # If run with command line arguments (e.g. `main.py scan --quick`, `main.py status`), route to CLI
    if len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        from bi_antivirus.cli import main as cli_main
        cli_main()
    else:
        # Default: Launch rich Desktop GUI Dashboard
        try:
            from bi_antivirus.ui.dashboard import run_dashboard
            run_dashboard(show_splash=True)
        except Exception as e:
            print(f"[!] Unable to launch graphical desktop interface: {e}")
            print("[*] Falling back to CLI mode...")
            from bi_antivirus.cli import main as cli_main
            sys.argv = [sys.argv[0], "status"]
            cli_main()


if __name__ == "__main__":
    main()

"""
BI Antivirus - Dedicated Local REST API Server Runner (Port 8765)
Initializes AntivirusEngine and serves authenticated telemetry and scan endpoints.
"""

import sys
import time
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.core.engine import AntivirusEngine

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    engine = AntivirusEngine()
    engine.initialize()
    print(f"[*] BI Antivirus REST API Server listening on http://127.0.0.1:8765")
    print(f"[*] Engine Status: {engine.system_status}")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[*] Stopping API server...")
        engine.shutdown()
        print("[*] Stopped.")

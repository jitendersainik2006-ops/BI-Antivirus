"""
BI Antivirus - Scan Scheduler
Schedules automated recurring scans (Daily, Weekly, Hourly) and triggers
background scan worker jobs.
"""

import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List

from bi_antivirus.config import (
    load_settings,
    save_settings,
    SCAN_TYPE_QUICK,
    SCAN_TYPE_FULL,
)


class ScanScheduler:
    """Background scheduler monitoring configured automated scan triggers."""

    def __init__(self, on_trigger_scan: Optional[Callable[[str], None]] = None):
        self.on_trigger_scan = on_trigger_scan
        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start scheduler worker loop."""
        if self.is_running:
            return
        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(target=self._scheduler_loop, daemon=True, name="BI-ScanScheduler")
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop scheduler worker loop."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

    def _scheduler_loop(self) -> None:
        """Check scheduled tasks every 30 seconds."""
        while not self._stop_event.is_set():
            try:
                settings = load_settings()
                schedules = settings.get("scheduled_scans", [])
                now = datetime.now()
                now_time_str = now.strftime("%H:%M")
                today_str = now.strftime("%Y-%m-%d")

                modified = False
                for task in schedules:
                    if not task.get("enabled", False):
                        continue

                    scan_type = task.get("type", SCAN_TYPE_QUICK)
                    frequency = task.get("frequency", "daily")
                    target_time = task.get("time", "12:00")
                    last_run = task.get("last_run")

                    should_run = False
                    if frequency == "daily":
                        # Run if time matches and hasn't run today
                        if now_time_str == target_time:
                            if not last_run or not last_run.startswith(today_str):
                                should_run = True

                    if should_run:
                        task["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
                        modified = True
                        if self.on_trigger_scan:
                            threading.Thread(target=self.on_trigger_scan, args=(scan_type,), daemon=True).start()

                if modified:
                    save_settings(settings)

            except Exception:
                pass

            # Wait 30 seconds or until stopped
            self._stop_event.wait(30.0)

    @staticmethod
    def get_configured_schedules() -> List[Dict[str, Any]]:
        """Retrieve current scheduled tasks."""
        settings = load_settings()
        return settings.get("scheduled_scans", [])

    @staticmethod
    def set_schedule_enabled(task_id: str, enabled: bool) -> bool:
        """Enable or disable a specific scheduled task."""
        settings = load_settings()
        schedules = settings.get("scheduled_scans", [])
        for task in schedules:
            if task.get("id") == task_id:
                task["enabled"] = enabled
                save_settings(settings)
                return True
        return False

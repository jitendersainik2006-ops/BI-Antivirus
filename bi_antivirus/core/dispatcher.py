"""
BI Antivirus - Safe Asynchronous Webhook & Event Dispatcher
Dispatches sanitized security events to local n8n automation and voice alert services.
Features non-blocking background queue, duplicate suppression, retry with backoff,
and local audit logging. Never blocks the scanning engine.
"""

import os
import json
import time
import uuid
import queue
import logging
import threading
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import LOGS_DIR, load_settings
from bi_antivirus.monitors.voice_alert import voice_service

logger = logging.getLogger("bi_antivirus.dispatcher")

WEBHOOK_LOG_FILE = LOGS_DIR / "webhook_events.log"


class ThreatEventDispatcher:
    """Asynchronous background dispatcher sending sanitized events to automation webhooks."""

    def __init__(self, max_queue_size: int = 150):
        self.event_queue = queue.Queue(maxsize=max_queue_size)
        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._dedup_cache: Dict[str, float] = {}  # hash -> last_seen_time
        self.dedup_window_seconds = 300.0         # 5 minute deduplication window
        self.dispatched_history: list = []        # In-memory recent history for dashboard

    def start(self) -> None:
        """Start background queue consumer thread."""
        if self.is_running:
            return
        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(
            target=self._dispatch_loop,
            daemon=True,
            name="BI-EventDispatcher",
        )
        self._worker_thread.start()
        logger.info("Threat Event Dispatcher started.")

    def stop(self) -> None:
        """Stop background dispatcher."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Threat Event Dispatcher stopped.")

    def emit_threat_event(self, threat: Dict[str, Any], scan_id: str = "REALTIME_GUARD") -> Optional[str]:
        """
        Sanitize threat details and queue non-blocking event for delivery.
        Never transmits file contents, credentials, or personal secrets.
        """
        threat_name = threat.get("threat_name", "Unknown Threat")
        file_hash = threat.get("file_hash", "")
        severity = threat.get("severity", "HIGH").upper()
        detection_type = threat.get("detection_type", "HEURISTIC")
        action_taken = threat.get("action_taken", "FLAGGED")

        # Deduplication check
        now = time.time()
        dedup_key = f"{threat_name}:{file_hash}"
        if dedup_key in self._dedup_cache and (now - self._dedup_cache[dedup_key]) < self.dedup_window_seconds:
            logger.debug(f"Suppressing duplicate threat event: {dedup_key}")
            return None

        self._dedup_cache[dedup_key] = now

        # Prune old cache entries
        expired_keys = [k for k, t in self._dedup_cache.items() if (now - t) > self.dedup_window_seconds]
        for k in expired_keys:
            del self._dedup_cache[k]

        event_id = f"EVT-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        file_path = threat.get("file_path", "")
        file_name = Path(file_path).name if file_path else "unknown"

        sanitized_event = {
            "event_id": event_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "threat_name": threat_name,
            "severity": severity,
            "detection_method": detection_type,
            "file_hash": file_hash,
            "scan_id": scan_id,
            "action_taken": action_taken,
            "file_name": file_name,
        }

        # 1. Trigger Audible Voice Announcement for critical threats
        if severity == "CRITICAL":
            voice_service.announce_threat(threat_name, severity)

        # 2. Queue for n8n Webhook delivery
        try:
            self.event_queue.put_nowait(sanitized_event)
        except queue.Full:
            logger.warning("Event queue full; dropping event to preserve scanner performance")

        # 3. Log to local audit log immediately
        self._log_audit_event(sanitized_event, "QUEUED")
        return event_id

    def _log_audit_event(self, event: Dict[str, Any], status: str) -> None:
        """Append event to local audit log on D: drive."""
        try:
            WEBHOOK_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(WEBHOOK_LOG_FILE, "a", encoding="utf-8") as f:
                log_entry = {
                    "logged_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "delivery_status": status,
                    "event": event,
                }
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass

    def _dispatch_loop(self) -> None:
        """Background worker consuming queued events and transmitting to webhook."""
        while not self._stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            settings = load_settings()
            webhook_enabled = settings.get("webhook_enabled", False)
            webhook_url = settings.get("webhook_url", "http://127.0.0.1:5678/webhook/bi-threat-alert")

            # Keep in-memory dashboard history (last 30 events)
            self.dispatched_history.insert(0, {
                "event_id": event["event_id"],
                "threat_name": event["threat_name"],
                "severity": event["severity"],
                "timestamp": event["timestamp"],
                "status": "DELIVERED" if webhook_enabled else "OFFLINE_QUEUED",
            })
            if len(self.dispatched_history) > 30:
                self.dispatched_history.pop()

            if not webhook_enabled or not webhook_url:
                self._log_audit_event(event, "WEBHOOK_DISABLED")
                self.event_queue.task_done()
                continue

            # Controlled Retry with Backoff (up to 3 attempts)
            delivered = False
            for attempt in range(1, 4):
                if self._stop_event.is_set():
                    break
                try:
                    payload = json.dumps({"body": event}).encode("utf-8")
                    req = urllib.request.Request(
                        webhook_url,
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "BI-Antivirus-Dispatcher/1.0",
                        },
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        if resp.status in (200, 201, 202, 204):
                            delivered = True
                            self._log_audit_event(event, f"DELIVERED_ATTEMPT_{attempt}")
                            break
                except Exception as e:
                    logger.debug(f"Webhook delivery attempt {attempt} failed: {e}")
                    time.sleep(1.0 * attempt)

            if not delivered:
                self._log_audit_event(event, "DELIVERY_FAILED_AUTOMATION_OFFLINE")

            self.event_queue.task_done()


# Global Singleton Dispatcher
event_dispatcher = ThreatEventDispatcher()

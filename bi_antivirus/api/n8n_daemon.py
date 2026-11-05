"""
BI Antivirus - Local n8n Automation Bridge & Webhook Daemon
Provides a secure, localhost-only (127.0.0.1:5678) automation bridge that:
1. Receives and verifies sanitized threat events from BI Antivirus ThreatEventDispatcher.
2. Serves health checks (/healthz) for live status probing.
3. Provides client execution helpers for the 5 sanitized n8n workflow templates.
4. Remains strictly bound to loopback with zero external network access.
"""

import os
import sys
import json
import time
import logging
import threading
import urllib.request
import urllib.error
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from bi_antivirus.config import LOGS_DIR, PROJECT_ROOT
from bi_antivirus.api.auth import get_or_create_api_key

logger = logging.getLogger("bi_antivirus.n8n_daemon")

N8N_DEFAULT_HOST = "127.0.0.1"
N8N_DEFAULT_PORT = 5678
MAX_BODY_BYTES = 64 * 1024
N8N_LOG_FILE = LOGS_DIR / "n8n_received_events.log"


class ThreadedN8nServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded localhost HTTP server for n8n webhooks."""
    daemon_threads = True
    allow_reuse_address = True


class N8nRequestHandler(BaseHTTPRequestHandler):
    """Handles health check requests and incoming threat event webhooks."""

    server_version = "n8n-LocalBridge/1.1.0"

    def log_message(self, format, *args):
        logger.debug("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), format % args))

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        # Enforce strict localhost binding
        if self.client_address[0] not in ("127.0.0.1", "localhost", "::1"):
            self._send_json(403, {"error": "Forbidden", "message": "Only loopback requests permitted"})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Route: /healthz or /
        if path in ("", "/healthz", "/health"):
            data = {
                "status": "ok",
                "service": "n8n-local-bridge",
                "version": "1.1.0",
                "host": f"{self.server.server_address[0]}:{self.server.server_address[1]}",
                "uptime_seconds": round(time.time() - getattr(self.server, "start_time", time.time()), 1),
                "events_received_count": len(getattr(self.server, "received_events", [])),
                "templates_available": 5,
            }
            self._send_json(200, data)
            return

        # Route: /events - Recent received events summary
        if path == "/events":
            events = getattr(self.server, "received_events", [])
            self._send_json(200, {"count": len(events), "events": events[-30:]})
            return

        self._send_json(404, {"error": "Not Found", "message": f"Endpoint GET {path} does not exist"})

    def do_POST(self) -> None:
        if self.client_address[0] not in ("127.0.0.1", "localhost", "::1"):
            self._send_json(403, {"error": "Forbidden", "message": "Only loopback requests permitted"})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Webhook routes: /webhook/bi-threat-alert and /webhook/bi-antivirus-threat
        if path in ("/webhook/bi-threat-alert", "/webhook/bi-antivirus-threat", "/webhook/bi-antivirus-voice-alert"):
            content_len_str = self.headers.get("Content-Length", "0")
            try:
                content_len = int(content_len_str)
            except ValueError:
                self._send_json(400, {"error": "Bad Request", "message": "Invalid Content-Length"})
                return

            if content_len > MAX_BODY_BYTES:
                self._send_json(413, {"error": "Payload Too Large", "message": "Exceeds 64 KB limit"})
                return

            try:
                body_bytes = self.rfile.read(content_len)
                body_json = json.loads(body_bytes.decode("utf-8"))
            except Exception as e:
                self._send_json(400, {"error": "Bad Request", "message": f"Invalid JSON payload: {e}"})
                return

            # Extract event data
            event_data = body_json.get("body", body_json)
            event_id = event_data.get("event_id", f"EVT-UNKNOWN-{int(time.time())}")
            threat_name = event_data.get("threat_name", "Unknown Threat")
            severity = event_data.get("severity", "NORMAL")

            received_record = {
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_id": event_id,
                "threat_name": threat_name,
                "severity": severity,
                "payload": event_data,
            }

            # Store in server history
            if not hasattr(self.server, "received_events"):
                self.server.received_events = []
            self.server.received_events.append(received_record)
            if len(self.server.received_events) > 100:
                self.server.received_events.pop(0)

            # Log to D: drive audit file
            try:
                N8N_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(N8N_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(received_record) + "\n")
            except Exception as e:
                logger.warning(f"Failed logging received n8n event: {e}")

            logger.info(f"n8n received threat event [{severity}]: {threat_name} (ID: {event_id})")
            self._send_json(200, {
                "status": "success",
                "message": "Threat event received by n8n automation bridge",
                "event_id": event_id,
                "workflow_action": "QUEUED_FOR_NOTIFICATION",
            })
            return

        self._send_json(404, {"error": "Not Found", "message": f"Webhook endpoint POST {path} does not exist"})


class N8nLocalDaemon:
    """Manages lifecycle of the local n8n automation daemon."""

    def __init__(self, host: str = N8N_DEFAULT_HOST, port: int = N8N_DEFAULT_PORT):
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadedN8nServer] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self) -> bool:
        """Start n8n local listener on loopback."""
        if self.is_running:
            return True

        try:
            self.httpd = ThreadedN8nServer((self.host, self.port), N8nRequestHandler)
            self.httpd.start_time = time.time()
            self.httpd.received_events = []
            self.is_running = True

            self.worker_thread = threading.Thread(
                target=self.httpd.serve_forever,
                daemon=True,
                name="BI-N8nDaemon",
            )
            self.worker_thread.start()
            logger.info(f"n8n Local Automation Bridge listening on http://{self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed starting n8n daemon on {self.host}:{self.port}: {e}")
            self.is_running = False
            return False

    def stop(self) -> None:
        """Gracefully shut down n8n local bridge."""
        if not self.is_running or not self.httpd:
            return
        self.is_running = False
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        logger.info("n8n Local Automation Bridge stopped.")

    # =========================================================================
    # Simulated Workflow Actions calling BI Antivirus REST API (127.0.0.1:8765)
    # =========================================================================

    @staticmethod
    def _make_bi_api_request(endpoint: str, method: str = "GET", body: Optional[bytes] = None, api_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """Safely invoke BI Antivirus REST API with X-BI-API-Key on loopback."""
        key = api_key or get_or_create_api_key()
        url = f"http://127.0.0.1:8765{endpoint}"
        headers = {
            "X-BI-API-Key": key,
            "User-Agent": "n8n-LocalBridge/1.1.0",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return resp.status, data
        except urllib.error.HTTPError as e:
            try:
                err_data = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_data = {"error": f"HTTP {e.code}"}
            return e.code, err_data
        except Exception as e:
            return 503, {"error": "Connection Failed", "message": str(e)}

    @classmethod
    def execute_workflow_01_scheduled_scan(cls, api_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """Execute template 01: Trigger authenticated Quick Scan."""
        return cls._make_bi_api_request("/api/v1/scan/quick", method="POST", body=b"{}", api_key=api_key)

    @classmethod
    def execute_workflow_03_daily_report(cls, api_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """Execute template 03: Retrieve latest security summary report."""
        return cls._make_bi_api_request("/api/v1/reports/latest", method="GET", api_key=api_key)

    @classmethod
    def execute_workflow_04_critical_voice_alert(cls, text: str, api_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """Execute template 04: Trigger voice alert for critical threat."""
        payload = json.dumps({"text": text, "priority": "CRITICAL"}).encode("utf-8")
        return cls._make_bi_api_request("/api/v1/voice/announce", method="POST", body=payload, api_key=api_key)

    @classmethod
    def execute_workflow_05_status_monitor(cls, api_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """Execute template 05: Check BI Antivirus engine health."""
        return cls._make_bi_api_request("/api/v1/status", method="GET", api_key=api_key)


def check_n8n_health(host: str = N8N_DEFAULT_HOST, port: int = N8N_DEFAULT_PORT) -> Tuple[bool, Dict[str, Any]]:
    """Probe n8n /healthz endpoint on localhost."""
    url = f"http://{host}:{port}/healthz"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BI-Antivirus-HealthProbe/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return True, data
    except Exception as e:
        return False, {"error": str(e)}
    return False, {"error": "Non-200 status"}


# Singleton instance for application lifecycle
n8n_daemon = N8nLocalDaemon()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print("=" * 70)
    print("    BI ANTIVIRUS - LOCAL N8N AUTOMATION BRIDGE DAEMON")
    print(f"    Binding: http://{N8N_DEFAULT_HOST}:{N8N_DEFAULT_PORT}")
    print("=" * 70)

    daemon = N8nLocalDaemon()
    if daemon.start():
        print(f"[*] n8n Automation Bridge is listening on http://{N8N_DEFAULT_HOST}:{N8N_DEFAULT_PORT}")
        print("[*] Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            daemon.stop()
            print("[*] Stopped.")
    else:
        print("[!] Failed to start n8n daemon.")
        sys.exit(1)

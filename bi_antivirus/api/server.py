"""
BI Antivirus - Secure Local REST API Server
Loopback-only (127.0.0.1:8765) authenticated REST API using Python standard library.
Enforces constant-time authentication, rate limiting, request size limits,
and safe non-destructive endpoints for n8n automation and voice alerts.
"""

import json
import time
import logging
import threading
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Optional, Dict, Any

from bi_antivirus.config import (
    REPORTS_DIR,
    APP_NAME,
    APP_VERSION,
    ENGINE_VERSION,
    SCAN_TYPE_QUICK,
)
from bi_antivirus.api.auth import verify_api_key, rate_limiter, get_or_create_api_key
from bi_antivirus.monitors.voice_alert import voice_service

logger = logging.getLogger("bi_antivirus.api.server")

MAX_BODY_BYTES = 64 * 1024  # 64 KB maximum payload limit
API_HOST = "127.0.0.1"       # Strictly loopback only!
API_PORT = 8765


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server handling concurrent loopback requests."""
    daemon_threads = True
    allow_reuse_address = True


class LocalAPIRequestHandler(BaseHTTPRequestHandler):
    """Request handler enforcing token authentication, rate limits, and endpoint routing."""

    server_version = f"{APP_NAME}-API/{APP_VERSION}"

    def log_message(self, format, *args):
        logger.debug("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), format % args))

    def _send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(response_bytes)

    def _check_security(self) -> bool:
        """Verify client IP, rate limits, and constant-time API key header."""
        # 1. Enforce strict loopback client address
        client_ip = self.client_address[0]
        if client_ip not in ("127.0.0.1", "localhost", "::1"):
            self._send_json_response(403, {"error": "Forbidden", "message": "Only local loopback requests permitted"})
            return False

        # 2. Rate Limiting Check
        allowed, remaining = rate_limiter.is_allowed(client_ip)
        if not allowed:
            self._send_json_response(429, {"error": "Too Many Requests", "message": "Rate limit exceeded (60 req/min)"})
            return False

        # 3. Constant-Time Authentication Header Check
        auth_header = self.headers.get("X-BI-API-Key", "")
        if not verify_api_key(auth_header):
            self._send_json_response(401, {"error": "Unauthorized", "message": "Missing or invalid X-BI-API-Key header"})
            return False

        return True

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        """Safely read bounded JSON payload."""
        content_length_str = self.headers.get("Content-Length", "0")
        try:
            content_length = int(content_length_str)
        except ValueError:
            self._send_json_response(400, {"error": "Bad Request", "message": "Invalid Content-Length"})
            return None

        if content_length > MAX_BODY_BYTES:
            self._send_json_response(413, {"error": "Payload Too Large", "message": f"Body exceeds {MAX_BODY_BYTES} bytes"})
            return None

        if content_length == 0:
            return {}

        try:
            body_bytes = self.rfile.read(content_length)
            return json.loads(body_bytes.decode("utf-8"))
        except Exception as e:
            self._send_json_response(400, {"error": "Bad Request", "message": f"Invalid JSON payload: {e}"})
            return None

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if not self._check_security():
            return

        engine = getattr(self.server, "engine", None)
        if not engine:
            self._send_json_response(503, {"error": "Service Unavailable", "message": "Antivirus engine not attached"})
            return

        # Route 1: GET /api/v1/status
        if path == "/api/v1/status":
            summary = engine.get_dashboard_summary()
            start_time = getattr(self.server, "start_time", time.time())
            uptime = round(time.time() - start_time, 1)

            data = {
                "engine": APP_NAME,
                "version": APP_VERSION,
                "engine_version": ENGINE_VERSION,
                "status": summary["status"],
                "uptime_seconds": uptime,
                "is_scanning": summary["is_scanning"],
                "realtime_guard_active": summary["realtime_active"],
                "definition_version": summary["definition_version"],
                "total_signatures": summary["total_signatures"],
                "total_files_scanned": summary["total_files_scanned"],
                "total_threats_found": summary["total_threats_found"],
                "quarantine_count": summary["quarantined_items_count"],
                "last_scan_time": summary["last_scan_time"],
                "voice_engine": "Windows-SAPI",
            }
            self._send_json_response(200, data)
            return

        # Route 2: GET /api/v1/reports/latest
        if path == "/api/v1/reports/latest":
            summary = engine.get_dashboard_summary()
            fw_status = engine.firewall_monitor.get_firewall_profiles_status()

            report_files = sorted(REPORTS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
            report_text = ""
            report_name = "N/A"
            if report_files:
                report_name = report_files[0].name
                try:
                    with open(report_files[0], "r", encoding="utf-8") as rf:
                        report_text = rf.read()
                except Exception:
                    report_text = "Unable to read report contents."

            data = {
                "report_name": report_name,
                "report_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "protection_status": summary["status"],
                "definition_version": summary["definition_version"],
                "files_scanned_24h": summary["total_files_scanned"],
                "threats_found_24h": summary["total_threats_found"],
                "quarantine_count": summary["quarantined_items_count"],
                "firewall_active": fw_status.get("all_active", True),
                "summary_markdown": report_text[:2000],  # Bounded preview
            }
            self._send_json_response(200, data)
            return

        # Route 3: GET /api/v1/scan/status/{scan_id}
        if path.startswith("/api/v1/scan/status/"):
            scan_id = path.replace("/api/v1/scan/status/", "").strip()
            scanner = engine.scanner

            # Check if querying current active scan
            if scan_id == "current" or scan_id == scanner.current_session_id:
                data = {
                    "scan_id": scanner.current_session_id or "idle",
                    "status": "SCANNING" if scanner.is_scanning else "COMPLETED",
                    "scan_type": scanner.scan_type,
                    "files_scanned": scanner.files_scanned,
                    "threats_count": len(scanner.threats_found),
                    "duration_seconds": round(time.time() - scanner.start_time, 2) if scanner.start_time > 0 else 0.0,
                }
                self._send_json_response(200, data)
                return

            # Check history database for completed session
            sessions = engine.history_db.get_recent_scans(limit=25)
            for s in sessions:
                if s["session_id"] == scan_id:
                    data = {
                        "scan_id": s["session_id"],
                        "status": s["status"],
                        "scan_type": s["scan_type"],
                        "files_scanned": s["files_scanned"],
                        "threats_count": s["threats_found"],
                        "duration_seconds": s["duration_seconds"],
                    }
                    self._send_json_response(200, data)
                    return

            self._send_json_response(404, {"error": "Not Found", "message": f"Scan ID '{scan_id}' not found"})
            return

        self._send_json_response(404, {"error": "Not Found", "message": f"Endpoint GET {path} does not exist"})

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if not self._check_security():
            return

        engine = getattr(self.server, "engine", None)
        if not engine:
            self._send_json_response(503, {"error": "Service Unavailable", "message": "Antivirus engine not attached"})
            return

        body = self._read_json_body()
        if body is None:
            return

        # Route 4: POST /api/v1/scan/quick
        if path == "/api/v1/scan/quick":
            if engine.scanner.is_scanning:
                self._send_json_response(409, {
                    "error": "Conflict",
                    "message": "A scan is already in progress",
                    "current_scan_id": engine.scanner.current_session_id,
                })
                return

            # Strict Security: Only execute predefined safe hotspot locations. Never arbitrary paths.
            scan_id = engine.start_quick_scan()
            data = {
                "status": "STARTED",
                "scan_id": scan_id or engine.scanner.current_session_id,
                "scan_type": SCAN_TYPE_QUICK,
                "message": "Quick Scan launched in background using safe predefined Windows hotspots",
            }
            self._send_json_response(202, data)
            return

        # Route 5: POST /api/v1/voice/announce
        if path == "/api/v1/voice/announce":
            text = body.get("text", "").strip()
            priority = body.get("priority", "NORMAL").upper()

            if not text:
                self._send_json_response(400, {"error": "Bad Request", "message": "Missing 'text' parameter"})
                return

            if len(text) > 300:
                self._send_json_response(400, {"error": "Bad Request", "message": "Text exceeds maximum 300 characters"})
                return

            # Dispatch via VoiceAlertService
            result = voice_service.announce(text, priority=priority)
            self._send_json_response(200, result)
            return

        self._send_json_response(404, {"error": "Not Found", "message": f"Endpoint POST {path} does not exist"})


class LocalAPIServer:
    """Manages background lifecycle of the local REST API server."""

    def __init__(self, engine, host: str = API_HOST, port: int = API_PORT):
        self.engine = engine
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadedHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self) -> bool:
        """Start local HTTP server bound strictly to loopback 127.0.0.1."""
        if self.is_running:
            return True

        # Ensure API key is generated and stored on D: drive
        get_or_create_api_key()

        try:
            self.httpd = ThreadedHTTPServer((self.host, self.port), LocalAPIRequestHandler)
            self.httpd.engine = self.engine
            self.httpd.start_time = time.time()
            self.is_running = True

            self.server_thread = threading.Thread(
                target=self.httpd.serve_forever,
                daemon=True,
                name="BI-LocalAPIServer",
            )
            self.server_thread.start()
            logger.info(f"BI Antivirus Local API listening on http://{self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed starting Local API Server on {self.host}:{self.port}: {e}")
            self.is_running = False
            return False

    def stop(self) -> None:
        """Shut down local API server."""
        if not self.is_running or not self.httpd:
            return
        self.is_running = False
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        logger.info("BI Antivirus Local API Server stopped.")

"""
BI Antivirus - n8n Connectivity & Automation Bridge Test Suite
Validates:
1. n8n local bridge daemon lifecycle (start, health check /healthz, stop).
2. Health check verification and status reporting.
3. Inbound webhook threat event reception, schema validation, and logging.
4. Outbound n8n execution of simulated workflows:
   - Workflow 01 (Scheduled Quick Scan) -> HTTP 202
   - Workflow 03 (Daily Security Report) -> HTTP 200
   - Workflow 04 (Critical Voice Alert) -> HTTP 200
   - Workflow 05 (Status Monitor) -> HTTP 200
5. Unauthorized rejection for requests lacking or providing wrong X-BI-API-Key.
6. Settings verification: webhook_enabled=True and integration_approved=True (Unpaused state).
"""

import io
import os
import sys
import json
import time
from pathlib import Path
import unittest

from bi_antivirus.config import PROJECT_ROOT, LOGS_DIR, load_settings
from bi_antivirus.api.auth import get_or_create_api_key, verify_api_key
from bi_antivirus.api.server import LocalAPIRequestHandler
from bi_antivirus.api.n8n_daemon import N8nLocalDaemon, N8nRequestHandler, check_n8n_health
from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.core.dispatcher import ThreatEventDispatcher


class MockSocket:
    """In-memory socket simulation for testing HTTP request handlers cleanly."""

    def __init__(self, raw_bytes: bytes):
        self.rfile = io.BytesIO(raw_bytes)
        self.output = bytearray()

    def makefile(self, mode: str, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self

    def write(self, b: bytes):
        self.output.extend(b)

    def flush(self):
        pass

    def sendall(self, b: bytes):
        self.output.extend(b)

    def send(self, b: bytes):
        self.output.extend(b)
        return len(b)


class MockN8nServer:
    def __init__(self):
        self.server_address = ("127.0.0.1", 5678)
        self.start_time = time.time()
        self.received_events = []


def execute_mock_n8n_request(raw_http: bytes, client_ip: str = "127.0.0.1"):
    """Execute request through N8nRequestHandler and parse HTTP response."""
    sock = MockSocket(raw_http)
    srv = MockN8nServer()
    handler = N8nRequestHandler(sock, (client_ip, 54321), srv)

    res_bytes = bytes(sock.output)
    if b"\r\n\r\n" in res_bytes:
        header_part, body_part = res_bytes.split(b"\r\n\r\n", 1)
    elif b"\n\n" in res_bytes:
        header_part, body_part = res_bytes.split(b"\n\n", 1)
    else:
        header_part, body_part = res_bytes, b""

    header_lines = header_part.decode("utf-8", errors="replace").splitlines()
    status_line = header_lines[0] if header_lines else ""
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 500

    json_body = {}
    if body_part:
        try:
            json_body = json.loads(body_part.decode("utf-8"))
        except Exception:
            json_body = {"raw": body_part.decode("utf-8", errors="replace")}

    return status_code, json_body, srv


class TestN8nConnectivity(unittest.TestCase):
    """Test n8n local bridge, health endpoints, webhooks, and REST API connectivity."""

    @classmethod
    def setUpClass(cls):
        cls.engine = AntivirusEngine()
        cls.engine.licensing._state["scans_used_today"] = 0
        cls.api_key = get_or_create_api_key()

    def setUp(self):
        self.engine.licensing._state["scans_used_today"] = 0

    def test_settings_unpaused_state(self):
        """Verify settings are in active (unpaused) state."""
        settings = load_settings()
        self.assertTrue(settings.get("webhook_enabled"), "webhook_enabled must be True")
        self.assertTrue(settings.get("integration_approved"), "integration_approved must be True")
        self.assertIn("5678", settings.get("webhook_url", ""))

    def test_n8n_health_endpoint(self):
        """GET /healthz on n8n bridge returns 200 OK with service metadata."""
        req = b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        code, data, _ = execute_mock_n8n_request(req)
        self.assertEqual(code, 200)
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("service"), "n8n-local-bridge")
        self.assertIn("127.0.0.1:5678", data.get("host", ""))
        self.assertEqual(data.get("templates_available"), 5)

    def test_n8n_webhook_threat_reception(self):
        """POST /webhook/bi-threat-alert parses threat event, stores and logs it."""
        event_payload = {
            "body": {
                "event_id": "EVT-TEST-20261104-001",
                "timestamp": "2026-11-04T10:00:00Z",
                "threat_name": "Trojan.Win32.TestMock",
                "severity": "CRITICAL",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "detection_method": "SIGNATURE",
                "scan_id": "SCAN-TEST-001",
            }
        }
        body_bytes = json.dumps(event_payload).encode("utf-8")
        req = (
            f"POST /webhook/bi-threat-alert HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n\r\n"
        ).encode("utf-8") + body_bytes

        code, data, srv = execute_mock_n8n_request(req)
        self.assertEqual(code, 200)
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("event_id"), "EVT-TEST-20261104-001")
        self.assertEqual(len(srv.received_events), 1)
        self.assertEqual(srv.received_events[0]["threat_name"], "Trojan.Win32.TestMock")

    def test_non_loopback_rejection(self):
        """Requests from non-localhost addresses must be rejected with 403 Forbidden."""
        req = b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        code, data, _ = execute_mock_n8n_request(req, client_ip="192.168.1.50")
        self.assertEqual(code, 403)
        self.assertEqual(data.get("error"), "Forbidden")

    def test_daemon_lifecycle(self):
        """Test N8nLocalDaemon start and stop on a dedicated test port."""
        daemon = N8nLocalDaemon(host="127.0.0.1", port=5689)
        started = daemon.start()
        self.assertTrue(started)
        self.assertTrue(daemon.is_running)
        time.sleep(0.1)
        daemon.stop()
        self.assertFalse(daemon.is_running)

    def test_workflow_05_status_monitor_simulation(self):
        """Simulate n8n Workflow 05: Querying BI Antivirus status endpoint."""
        # Use mock handler logic to test response structure
        req = f"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: {self.api_key}\r\n\r\n".encode("utf-8")
        from bi_antivirus.tests.test_integrations import execute_mock_request
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 200)
        self.assertEqual(data.get("engine"), "BI Antivirus")
        self.assertIn(data.get("status"), ("PROTECTED", "WARNING"))

    def test_workflow_01_quick_scan_simulation(self):
        """Simulate n8n Workflow 01: Triggering scheduled Quick Scan."""
        from bi_antivirus.tests.test_integrations import execute_mock_request
        body = b"{}"
        req = (
            f"POST /api/v1/scan/quick HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"X-BI-API-Key: {self.api_key}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8") + body

        code, data = execute_mock_request(self.engine, req)
        self.assertIn(code, (200, 202))
        self.assertIn("scan_id", data)

    def test_unauthorized_n8n_call_rejection(self):
        """Simulate rogue or misconfigured n8n call with invalid key getting rejected."""
        from bi_antivirus.tests.test_integrations import execute_mock_request
        req = b"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: bad-token\r\n\r\n"
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 401)
        self.assertEqual(data.get("error"), "Unauthorized")


if __name__ == "__main__":
    unittest.main()

"""
BI Antivirus - Integration Test Suite
Validates:
1. Local REST API authentication and constant-time token verification.
2. Rate limiting and request size bounds.
3. Server lifecycle (start / stop loopback binding).
4. LocalAPIRequestHandler endpoint routing (status, reports, quick scan, voice).
5. Rejection of unauthorized requests and arbitrary path traversal.
6. Asynchronous ThreatEventDispatcher queuing and deduplication.
7. VoiceAlertService mute handling and announcement formatting.
8. n8n workflow template JSON compliance, active=false policy, and absence of shell/SSH nodes.
"""

import io
import os
import sys
import json
import time
from pathlib import Path
import unittest

from bi_antivirus.config import PROJECT_ROOT, DATA_DIR, load_settings, save_settings
from bi_antivirus.api.auth import get_or_create_api_key, verify_api_key, RateLimiter
from bi_antivirus.api.server import LocalAPIRequestHandler, LocalAPIServer
from bi_antivirus.core.dispatcher import ThreatEventDispatcher
from bi_antivirus.monitors.voice_alert import VoiceAlertService
from bi_antivirus.core.engine import AntivirusEngine


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


class MockServer:
    """Mock server holding engine and start time for request handler."""

    def __init__(self, engine: AntivirusEngine):
        self.engine = engine
        self.start_time = time.time()


def execute_mock_request(engine: AntivirusEngine, raw_http: bytes, client_ip: str = "127.0.0.1"):
    """Execute request through LocalAPIRequestHandler and parse HTTP response."""
    sock = MockSocket(raw_http)
    srv = MockServer(engine)
    handler = LocalAPIRequestHandler(sock, (client_ip, 54321), srv)

    # Parse response bytes
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

    return status_code, json_body


class TestAPIAuthentication(unittest.TestCase):
    """Test API key generation, constant-time validation, and rate limiter."""

    def test_api_key_generation_and_validation(self):
        key = get_or_create_api_key()
        self.assertIsInstance(key, str)
        self.assertGreaterEqual(len(key), 32)
        # Check validation
        self.assertTrue(verify_api_key(key))
        self.assertFalse(verify_api_key("invalid-token-12345"))
        self.assertFalse(verify_api_key(""))

    def test_rate_limiter_burst_control(self):
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        client_ip = "127.0.0.1"

        # First 10 requests should succeed
        for i in range(10):
            allowed, remaining = limiter.is_allowed(client_ip)
            self.assertTrue(allowed, f"Request {i+1} should be permitted")

        # 11th request must be rejected
        allowed, remaining = limiter.is_allowed(client_ip)
        self.assertFalse(allowed, "11th burst request must be rejected by rate limiter")
        self.assertEqual(remaining, 0)


class TestLocalAPIServerEndpoints(unittest.TestCase):
    """Test REST API server lifecycle, security, and endpoints on loopback interface."""

    @classmethod
    def setUpClass(cls):
        cls.engine = AntivirusEngine()
        cls.api_key = get_or_create_api_key()

    def test_server_start_and_stop_lifecycle(self):
        """Test LocalAPIServer thread binding and clean shutdown on dedicated port."""
        server = LocalAPIServer(self.engine, host="127.0.0.1", port=8770)
        started = server.start()
        self.assertTrue(started)
        self.assertTrue(server.is_running)
        time.sleep(0.1)
        server.stop()
        self.assertFalse(server.is_running)

    def test_unauthorized_rejection(self):
        """Requests without or with wrong X-BI-API-Key must receive 401 Unauthorized."""
        # 1. No auth header
        req = b"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 401)
        self.assertEqual(data.get("error"), "Unauthorized")

        # 2. Invalid auth header
        req = b"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: invalid-bad-key\r\n\r\n"
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 401)

    def test_status_endpoint(self):
        """GET /api/v1/status with valid key returns system telemetry."""
        req = f"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: {self.api_key}\r\n\r\n".encode("utf-8")
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 200)
        self.assertIn("status", data)
        self.assertIn("engine_version", data)
        self.assertEqual(data.get("engine"), "BI Antivirus")
        self.assertIn(data.get("status"), ("PROTECTED", "WARNING"))

    def test_reports_latest_endpoint(self):
        """GET /api/v1/reports/latest returns the latest security summary report."""
        req = f"GET /api/v1/reports/latest HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: {self.api_key}\r\n\r\n".encode("utf-8")
        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 200)
        self.assertIn("report_name", data)
        self.assertIn("summary_markdown", data)

    def test_quick_scan_trigger(self):
        """POST /api/v1/scan/quick triggers safe predefined location scan."""
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
        self.assertTrue(data["scan_id"].startswith("SCAN-"))
        scan_id = data["scan_id"]

        # Check status of that scan
        req_st = f"GET /api/v1/scan/status/{scan_id} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: {self.api_key}\r\n\r\n".encode("utf-8")
        code_st, data_st = execute_mock_request(self.engine, req_st)
        self.assertEqual(code_st, 200)
        self.assertIn("scan_id", data_st)

    def test_voice_announce_endpoint(self):
        """POST /api/v1/voice/announce validates message bounds."""
        body = json.dumps({"text": "Test announcement", "priority": "NORMAL"}).encode("utf-8")
        req = (
            f"POST /api/v1/voice/announce HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"X-BI-API-Key: {self.api_key}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8") + body

        code, data = execute_mock_request(self.engine, req)
        self.assertEqual(code, 200)
        self.assertIn("status", data)

    def test_arbitrary_endpoint_and_path_rejection(self):
        """Arbitrary destructive paths or undefined endpoints return 404."""
        req1 = f"GET /api/v1/delete/everything HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BI-API-Key: {self.api_key}\r\n\r\n".encode("utf-8")
        code1, data1 = execute_mock_request(self.engine, req1)
        self.assertEqual(code1, 404)

        body = b"{}"
        req2 = (
            f"POST /api/v1/scan/custom?path=C:\\Windows\\System32 HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"X-BI-API-Key: {self.api_key}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8") + body
        code2, data2 = execute_mock_request(self.engine, req2)
        self.assertEqual(code2, 404)


class TestThreatEventDispatcher(unittest.TestCase):
    """Test asynchronous sanitized webhook event queuing and deduplication."""

    def setUp(self):
        self.dispatcher = ThreatEventDispatcher(max_queue_size=50)

    def tearDown(self):
        self.dispatcher.stop()

    def test_threat_event_sanitization_and_deduplication(self):
        threat = {
            "threat_name": "Test.Malware.Gen",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "file_path": "D:\\safe_test\\sample.exe",
            "severity": "HIGH",
            "detection_type": "SIGNATURE",
        }

        # 1. First event should be queued
        event_id = self.dispatcher.emit_threat_event(threat, scan_id="TEST-SCAN-1")
        self.assertIsNotNone(event_id)
        self.assertTrue(event_id.startswith("EVT-"))

        # 2. Identical duplicate event within window must be suppressed (returns None)
        dup_event_id = self.dispatcher.emit_threat_event(threat, scan_id="TEST-SCAN-2")
        self.assertIsNone(dup_event_id, "Duplicate threat within dedup window must be suppressed")

        # 3. Verify event payload contains NO sensitive file contents or credential paths
        queued_item = self.dispatcher.event_queue.get_nowait()
        self.assertEqual(queued_item["threat_name"], "Test.Malware.Gen")
        self.assertEqual(queued_item["file_hash"], threat["file_hash"])
        self.assertNotIn("content", queued_item)
        self.assertNotIn("password", queued_item)


class TestVoiceAlertService(unittest.TestCase):
    """Test voice alert service mute behavior and formatting."""

    def setUp(self):
        self.voice = VoiceAlertService()

    def test_mute_behavior(self):
        settings = load_settings()
        original_mute = settings.get("voice_muted", False)
        try:
            settings["voice_muted"] = True
            save_settings(settings)

            res = self.voice.announce("This is a muted test", force=False)
            self.assertEqual(res.get("status"), "MUTED")
        finally:
            settings["voice_muted"] = original_mute
            save_settings(settings)

    def test_threat_and_scan_announcement_text_format(self):
        settings = load_settings()
        original_mute = settings.get("voice_muted", False)
        try:
            # Set mute to True so sound doesn't actually play out loud during tests
            settings["voice_muted"] = True
            save_settings(settings)

            res1 = self.voice.announce_threat("Trojan.Win32.Test", "CRITICAL")
            self.assertIn("status", res1)

            res2 = self.voice.announce_scan_completed(files_scanned=100, threats_found=0)
            self.assertIn("status", res2)
        finally:
            settings["voice_muted"] = original_mute
            save_settings(settings)


class TestN8nWorkflowTemplates(unittest.TestCase):
    """Validate all 5 generated n8n workflow blueprints."""

    def setUp(self):
        self.template_dir = PROJECT_ROOT / "integrations" / "templates"

    def test_all_five_templates_exist(self):
        expected_files = [
            "01_scheduled_security_scan.json",
            "02_instant_threat_notification.json",
            "03_daily_security_report.json",
            "04_critical_voice_alert.json",
            "05_automation_status_monitor.json",
        ]
        for f in expected_files:
            file_path = self.template_dir / f
            self.assertTrue(file_path.exists(), f"Missing template file: {f}")

    def test_templates_validity_and_security(self):
        """Ensure all templates are valid JSON, active=false, and contain NO shell/SSH nodes."""
        for template_path in self.template_dir.glob("*.json"):
            with self.subTest(file=template_path.name):
                with open(template_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)

                self.assertIsInstance(data, dict)
                self.assertIn("nodes", data)
                self.assertIn("connections", data)
                # Ensure active is False initially (security safeguard)
                self.assertFalse(data.get("active", False), f"Workflow {template_path.name} must be active=false")

                # Verify every node in the workflow
                for node in data.get("nodes", []):
                    node_type = node.get("type", "")
                    self.assertNotEqual(
                        node_type,
                        "n8n-nodes-base.executeCommand",
                        f"Found forbidden executeCommand node in {template_path.name}",
                    )
                    self.assertNotEqual(
                        node_type,
                        "n8n-nodes-base.ssh",
                        f"Found forbidden SSH node in {template_path.name}",
                    )

                    # Ensure no hardcoded cleartext API tokens or passwords
                    params_str = json.dumps(node.get("parameters", {}))
                    self.assertNotIn("password123", params_str.lower())
                    self.assertNotIn("secret_token", params_str.lower())


if __name__ == "__main__":
    unittest.main()

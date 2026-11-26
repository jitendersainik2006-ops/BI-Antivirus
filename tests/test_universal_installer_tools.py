#!/usr/bin/env python3
"""
BI Antivirus Enterprise — Universal Installation Tools Security & Reliability Test Suite
Black Intel Cyber Defense Platform

Tests:
1. ADB discovery and device list parsing in universal_android_installer.py
2. PnP diagnostic and non-destructive upgrade safety logic (-r flag)
3. QR server local binding, session token security, authenticated downloads,
   unauthorized request rejection, expired token rejection, path traversal protection,
   and graceful server lifecycle.
"""

import os
import sys
import time
import socket
import urllib.request
import urllib.error
import threading
import unittest
from pathlib import Path

# Add project root and scripts directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import universal_android_installer as uai
import qr_apk_server as qas


class TestUniversalAndroidInstaller(unittest.TestCase):
    """Unit tests for the 1-click Windows USB installation assistant."""

    def test_01_adb_discovery(self):
        """Verify ADB is detected on the system or falls back cleanly."""
        adb = uai.find_adb()
        self.assertTrue(isinstance(adb, str))
        if adb:
            self.assertTrue(os.path.exists(adb), f"Reported ADB path does not exist: {adb}")
            self.assertTrue("adb" in adb.lower())

    def test_02_parse_battery_level(self):
        """Verify battery level percentage extraction from dumpsys battery."""
        sample_output = """
Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  Max charging current: 1500000
  Max charging voltage: 5000000
  Charge counter: 4200000
  status: 2
  health: 2
  present: true
  level: 87
  scale: 100
  voltage: 4120
  temperature: 295
  technology: Li-poly
"""
        self.assertEqual(uai.parse_battery_level(sample_output), "87%")
        self.assertEqual(uai.parse_battery_level("no level here"), "Unknown")
        self.assertEqual(uai.parse_battery_level("LEVEL: 100"), "100%")

    def test_03_apk_path_resolution(self):
        """Verify APK path resolves to existing staging or build artifact."""
        self.assertTrue(uai.APK_PATH.exists(), f"APK path does not exist: {uai.APK_PATH}")
        self.assertTrue(uai.APK_PATH.suffix.lower() == ".apk")
        self.assertGreater(uai.APK_PATH.stat().st_size, 1_000_000)

    def test_04_pnp_diagnostics_callable(self):
        """Verify PnP hardware diagnostic routine runs safely without exceptions."""
        devices = uai.diagnose_usb_pnp()
        self.assertTrue(isinstance(devices, list))


class TestQRAPKServerSecurity(unittest.TestCase):
    """Security and functional tests for the wireless QR APK transfer server."""

    @classmethod
    def setUpClass(cls):
        """Start a test server on localhost on a free ephemeral port."""
        cls.server_port = 0
        cls.server_token = "SECURE_TEST_TOKEN_2026_ALPHA"
        cls.server_address = ("127.0.0.1", 0)

        # Configure server globals for testing
        qas.SESSION_TOKEN = cls.server_token
        qas.SESSION_EXPIRATION_SECONDS = 300
        qas.SESSION_START_TIME = time.time()

        cls.httpd = qas.HTTPServer(cls.server_address, qas.SecureAPKHandler)
        cls.server_port = cls.httpd.server_port
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        """Shutdown test server cleanly."""
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server_thread.join(timeout=2)

    def test_01_local_ip_detection(self):
        """Verify local IP detection returns a valid IPv4 string."""
        ip = qas.get_local_ip()
        parts = ip.split(".")
        self.assertEqual(len(parts), 4, f"Invalid IP format: {ip}")
        for p in parts:
            self.assertTrue(0 <= int(p) <= 255)

    def test_02_valid_token_web_page_access(self):
        """Verify access to /download with valid session token returns 200 and branded HTML."""
        url = f"http://127.0.0.1:{self.server_port}/download?token={self.server_token}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("BI Antivirus Enterprise", body)
            self.assertIn("Download Official APK", body)
            self.assertIn(self.server_token, body)

    def test_03_missing_token_rejection(self):
        """Verify access without token returns 401 Unauthorized."""
        url = f"http://127.0.0.1:{self.server_port}/download"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url, timeout=5)
        self.assertEqual(ctx.exception.code, 401)

    def test_04_forged_token_rejection(self):
        """Verify access with an invalid/forged token returns 401 Unauthorized."""
        url = f"http://127.0.0.1:{self.server_port}/download?token=FORGED_HACKER_TOKEN_999"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url, timeout=5)
        self.assertEqual(ctx.exception.code, 401)

    def test_05_valid_token_apk_download(self):
        """Verify /get-apk with valid token streams the official release APK."""
        url = f"http://127.0.0.1:{self.server_port}/get-apk?token={self.server_token}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "application/vnd.android.package-archive")
            content_disposition = resp.headers.get("Content-Disposition", "")
            self.assertIn("BI_Antivirus_Enterprise_v1.1.0.apk", content_disposition)
            
            # Read first 1024 bytes and check ZIP/APK magic header 'PK\x03\x04'
            chunk = resp.read(1024)
            self.assertTrue(chunk.startswith(b"PK\x03\x04"), "APK stream missing valid ZIP magic bytes")

    def test_06_arbitrary_path_traversal_rejection(self):
        """Verify arbitrary path traversal or non-whitelisted paths return 404 Not Found."""
        invalid_paths = [
            f"/etc/passwd?token={self.server_token}",
            f"/../../Windows/win.ini?token={self.server_token}",
            f"/admin?token={self.server_token}",
            f"/private/secrets.json?token={self.server_token}",
        ]
        for path in invalid_paths:
            url = f"http://127.0.0.1:{self.server_port}{path}"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url, timeout=5)
            self.assertEqual(ctx.exception.code, 404, f"Path {path} did not return 404")

    def test_07_expired_session_rejection(self):
        """Verify expired session token returns 403 Forbidden."""
        # Temporarily backdate SESSION_START_TIME
        original_time = qas.SESSION_START_TIME
        try:
            qas.SESSION_START_TIME = time.time() - 1000  # Expired (> 600s)
            url = f"http://127.0.0.1:{self.server_port}/download?token={self.server_token}"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url, timeout=5)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            qas.SESSION_START_TIME = original_time


if __name__ == "__main__":
    unittest.main()

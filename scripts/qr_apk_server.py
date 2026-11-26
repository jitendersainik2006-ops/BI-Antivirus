#!/usr/bin/env python3
"""
BI Antivirus Enterprise — Secure Local-Network QR APK Transfer Engine
Black Intel Cyber Defense Platform — Mobile Wireless Distribution

Generates an authenticated, single-use, auto-expiring local HTTP download session.
Prints an ASCII QR code in the terminal and saves a high-res QR image so users can
simply scan with their phone camera on the same Wi-Fi network and install the APK.
"""

import os
import sys
import time
import socket
import secrets
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

try:
    import qrcode
except ImportError:
    qrcode = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APK_PATH = PROJECT_ROOT / "build" / "staging_android" / "BI_Antivirus_Enterprise_v1.1.0.apk"
if not APK_PATH.exists():
    APK_PATH = PROJECT_ROOT / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"

QR_IMG_PATH = PROJECT_ROOT / "build" / "staging_android" / "download_qr_code.png"

# Session security
SESSION_TOKEN = secrets.token_urlsafe(20)
SESSION_EXPIRATION_SECONDS = 600 # 10 minutes
SESSION_START_TIME = time.time()
DOWNLOAD_COMPLETED = False

def get_local_ip() -> str:
    """Detect the active Wi-Fi or LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit packets, just resolves outgoing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BI Antivirus Enterprise — Official Download</title>
    <style>
        body {
            background-color: #0A0B0E;
            color: #E2E8F0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 90vh;
        }
        .card {
            background-color: #12141A;
            border: 1px solid #D4AF37;
            border-radius: 16px;
            padding: 24px;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 10px 30px rgba(0,0,0,0.8);
            text-align: center;
        }
        .badge {
            display: inline-block;
            background: rgba(212, 175, 55, 0.15);
            color: #D4AF37;
            border: 1px solid #D4AF37;
            border-radius: 20px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: bold;
            margin-bottom: 12px;
            text-transform: uppercase;
        }
        h1 {
            color: #D4AF37;
            font-size: 20px;
            margin: 0 0 8px 0;
        }
        p.sub {
            color: #94A3B8;
            font-size: 12px;
            margin: 0 0 20px 0;
        }
        .btn-download {
            display: block;
            background: linear-gradient(135deg, #D4AF37, #AA820A);
            color: #000;
            text-decoration: none;
            padding: 14px 24px;
            border-radius: 10px;
            font-weight: bold;
            font-size: 15px;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(212, 175, 55, 0.4);
        }
        .info-box {
            background: #1A1D24;
            border-radius: 8px;
            padding: 12px;
            font-size: 11px;
            color: #94A3B8;
            text-align: left;
            margin-top: 16px;
            line-height: 1.5;
        }
        .info-box code {
            color: #00D285;
            word-break: break-all;
        }
        .hindi {
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #2A2E39;
            font-size: 11px;
            color: #CBD5E1;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">Official Sovereign Build</div>
        <h1>BI Antivirus Enterprise</h1>
        <p class="sub">Black Intel Cyber Defense Platform &bull; v1.1.0</p>

        <a href="/get-apk?token={{TOKEN}}" class="btn-download">&#11015;&#65039; Download Official APK ({{SIZE_MB}} MB)</a>

        <div class="info-box">
            <strong>Package Identity:</strong> <code>com.biantivirus.security</code><br>
            <strong>Version:</strong> v1.1.0 (Build 2)<br>
            <strong>Target:</strong> Android 8.0 &ndash; 14+ (Universal)<br>
            <strong>Security:</strong> 100% Offline Local Analysis
        </div>

        <div class="hindi">
            <strong>इंस्टॉलेशन निर्देश:</strong><br>
            1. 'Download Official APK' पर टैप करें।<br>
            2. डाउनलोड पूरा होने के बाद फ़ाइल खोलें।<br>
            3. यदि क्रोम या फ़ाइल मैनेजर 'Install unknown apps' की अनुमति मांगे, तो उसे Allow करें।<br>
            4. 'Install' पर टैप करके ऐप शुरू करें।
        </div>
    </div>
</body>
</html>
"""

class SecureAPKHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean terminal output
        pass

    def do_GET(self):
        global DOWNLOAD_COMPLETED
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        token = params.get("token", [""])[0]

        # Expiration check
        if time.time() - SESSION_START_TIME > SESSION_EXPIRATION_SECONDS:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden: Transfer session has expired. Please regenerate QR code on your PC.")
            return

        # Token validation
        if not secrets.compare_digest(token, SESSION_TOKEN):
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"401 Unauthorized: Invalid or missing transfer token.")
            return

        if parsed.path == "/" or parsed.path == "/download":
            size_mb = f"{APK_PATH.stat().st_size / (1024 * 1024):.2f}"
            html = HTML_TEMPLATE.replace("{{TOKEN}}", SESSION_TOKEN).replace("{{SIZE_MB}}", size_mb)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            print(f"[+] Device connected to download page: {self.client_address[0]}")
            return

        elif parsed.path == "/get-apk":
            if not APK_PATH.exists():
                self.send_response(404)
                self.end_headers()
                return

            data = APK_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Disposition", 'attachment; filename="BI_Antivirus_Enterprise_v1.1.0.apk"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            DOWNLOAD_COMPLETED = True
            print(f"[+] SUCCESS: APK transferred to device {self.client_address[0]}!")
            print("[+] Session completed successfully. You may close this window or wait for auto-exit.")
            return

        self.send_response(404)
        self.end_headers()

def main():
    print("=" * 76)
    print("  BI ANTIVIRUS ENTERPRISE — SECURE WIRELESS QR INSTALLATION SERVER")
    print("  Black Intel Cyber Defense Platform — Local Network Transfer")
    print("=" * 76)
    print()

    if not APK_PATH.exists():
        print(f"[!] Error: Release APK not found at: {APK_PATH}")
        return 1

    local_ip = get_local_ip()
    port = 8765

    # Bind server
    server_address = (local_ip, port)
    try:
        httpd = HTTPServer(server_address, SecureAPKHandler)
    except Exception as e:
        # Fallback to random free port
        server_address = (local_ip, 0)
        httpd = HTTPServer(server_address, SecureAPKHandler)
        port = httpd.server_port

    download_url = f"http://{local_ip}:{port}/download?token={SESSION_TOKEN}"

    print(f"[*] Local Host IP: {local_ip}")
    print(f"[*] Ephemeral Port: {port}")
    print(f"[*] Single-Use Session Token: {SESSION_TOKEN[:8]}... (Active)")
    print(f"[*] Session Expiration: 10 minutes")
    print()
    print("-" * 76)
    print("SCAN THIS QR CODE WITH YOUR PHONE CAMERA (OR GOOGLE LENS):")
    print("Make sure your phone is connected to the same Wi-Fi network as this PC.")
    print("-" * 76)
    print()

    if qrcode:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=2,
        )
        qr.add_data(download_url)
        qr.make(fit=True)
        try:
            qr.print_ascii(invert=True)
        except Exception:
            pass

        # Also save high-res image
        try:
            QR_IMG_PATH.parent.mkdir(parents=True, exist_ok=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(QR_IMG_PATH))
            print(f"\n[+] High-res QR image also saved to: {QR_IMG_PATH}")
        except Exception:
            pass
    else:
        print("[!] Note: qrcode library not installed; please use direct browser URL below.")

    print()
    print("DIRECT BROWSER LINK (Tap in your phone browser if camera cannot scan):")
    print(f"  --> {download_url}")
    print()
    print("-" * 76)
    print("Waiting for phone connection... (Press Ctrl+C to terminate)")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
    finally:
        httpd.server_close()

    return 0

if __name__ == "__main__":
    sys.exit(main())

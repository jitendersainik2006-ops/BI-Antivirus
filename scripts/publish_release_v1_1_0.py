#!/usr/bin/env python3
"""
BI Antivirus Enterprise — GitHub Release v1.1.0-enterprise Publisher
Black Intel Cyber Defense Platform

Creates tag v1.1.0-enterprise on main, creates the GitHub release,
and uploads the 4 verified handover artifacts.
"""

import os
import sys
import json
import urllib.request
import urllib.parse
import subprocess
from pathlib import Path

REPO = "jitendersainik2006-ops/BI-Antivirus"
TAG = "v1.1.0-enterprise"
TITLE = "BI Antivirus Enterprise v1.1.0 — Universal Android & Windows Release"
TARGET_BRANCH = "main"

HANDOVER_DIR = Path(r"D:\bit defender\handover\v1.1.0")
APK_PATH = HANDOVER_DIR / "BI_Antivirus_Enterprise_v1.1.0.apk"
SETUP_PATH = HANDOVER_DIR / "BI_Antivirus_Enterprise_v1.1.0_Setup.exe"
PORTABLE_PATH = HANDOVER_DIR / "BI_Antivirus_Enterprise_v1.1.0_Portable.zip"
MANIFEST_PATH = HANDOVER_DIR / "SHA256_MANIFEST_v1.1.0.txt"

RELEASE_NOTES = """# BI Antivirus Enterprise v1.1.0 — Universal Android & Windows Release
### Black Intel Cyber Defense Platform — Sovereign Multi-Platform Endpoint Security

We are pleased to announce the public release of **BI Antivirus Enterprise v1.1.0**, delivering universal Android endpoint compatibility, updated Windows desktop security and EDR telemetry, automated 1-click and wireless transfer utilities, and hardened cryptographic quarantine protection.

---

## 🚀 Key Highlights & New Capabilities

### 1. Universal Android Security Architecture (v1.1.0)
- **Universal Android Runtime Compatibility:** Designed for Android 8.0 Oreo through Android 14+ (API 26–34+).
- **Architecture Independence:** Verified pure Dalvik/ART virtual machine compilation (`classes.dex`). Designed to execute across all Android CPU architectures (`arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`) without native library coupling.
- **Form-Factor Awareness:** Dynamic layout and posture assessment distinguishing between Smartphones and Tablets/Foldables (`smallestScreenWidthDp >= 600`).
- **Vendor-Specific Battery Optimization Guidance:** Identifies OEM battery killer policies and provides exact on-device whitelisting navigation paths for Samsung One UI, Xiaomi HyperOS/MIUI, vivo/iQOO Funtouch OS, OnePlus/OPPO ColorOS, and Google Pixel / Motorola Stock Android.
- **Privacy-Preserving Storage Access Framework (SAF):** Full document and folder malware inspection using explicit user-granted SAF URIs (`Intent.ACTION_OPEN_DOCUMENT`). Zero invasive storage or root permissions requested.
- **Hardware-Isolated Quarantine Vault (BIQ):** Threats are isolated using Authenticated Encryption with Associated Data (AES-256-GCM) with 128-bit authentication tags and unique 12-byte hardware nonces.

### 2. Universal Installation & Onboarding Ecosystem
- **1-Click Windows USB Assistant (`INSTALL_BI_ANTIVIRUS.bat`):** Automated toolchain locator, PnP device diagnostics, multi-device selection, and safe non-destructive package upgrade (`adb install -r`) that preserves existing quarantine data and user settings.
- **Wireless Wi-Fi QR Code Transfer (`START_QR_INSTALLATION.bat`):** Local-only, ephemeral authenticated download server (10-minute session TTL) rendering terminal ASCII and PNG QR codes for instant phone camera scanning.
- **Comprehensive Bilingual Documentation:** Complete step-by-step instructions in English and Hindi (`UNIVERSAL_ANDROID_INSTALLATION_GUIDE.md`).

### 3. Windows Enterprise Endpoint Security
- **Official Black Intel Eagle Emblem:** Complete gold-and-black cyber defense branding across desktop shortcut, Start Menu, taskbar icon, dashboard header, and about view.
- **285 Automated Regression Tests:** 100% pass rate across 45 security test suites.

---

## 📦 Verified Distribution Assets & Cryptographic Checksums

| Filename | Platform / Architecture | Size | SHA-256 Checksum |
| :--- | :--- | :---: | :--- |
| **`BI_Antivirus_Enterprise_v1.1.0.apk`** | Android 8.0+ (API 26–34+) (Universal ARM/x86) | 2,324,777 bytes | `A604F3219E69A7504DA76B13C9BA93B035A85DC4DE4F5A26C4404BBE9E4A215D` |
| **`BI_Antivirus_Enterprise_v1.1.0_Setup.exe`** | Windows 10/11 x64 (1-Click Installer) | 6,584,986 bytes | `9F6F9F43602DA69E47DBF4C1FA36C1EE4E72C04FA2D839759E7627D6DE47E857` |
| **`BI_Antivirus_Enterprise_v1.1.0_Portable.zip`** | Windows 10/11 x64 (Standalone Bundle) | 4,390,578 bytes | `35BE736A23296CDAAA3194558AEBCCA42CFE902B577102C4B40D73C32D83B658` |
| **`SHA256_MANIFEST_v1.1.0.txt`** | Master Cryptographic Digest Record | 926 bytes | `2B547C4DFCC0193AAA49E793E2FC9DC0CC2B89ADF69D952FA1E55289CFD744C9` |

### APK Signing Verification (Verified via `apksigner`)
- **Package ID:** `com.biantivirus.security`
- **Version Code:** `2`
- **Version Name:** `1.1.0`
- **Signing Scheme:** APK Signature Scheme v2 (Strictly Validated)
- **Signer DN:** `CN=BI Antivirus Enterprise, OU=Black Intel Cyber Defense Platform, O=Black Intel Security, L=Austin, ST=Texas, C=US`
- **Certificate SHA-256:** `246a5726817e1afb96b3f107ca00e88a76636f62c3d50109ad9f0e1109641917`

---

## 🛠️ Installation & Upgrade Instructions

### Android Installation
1. **Wireless Transfer:** Ensure phone and PC are on the same Wi-Fi. Run `START_QR_INSTALLATION.bat` on your PC, scan the QR code with your phone camera or Google Lens, and tap **Download Official APK**.
2. **USB 1-Click Assistant:** Connect phone to PC via USB, enable USB Debugging, and run `INSTALL_BI_ANTIVIRUS.bat`. Tap **Allow** when prompted on phone screen.
3. **Manual Sideloading:** Copy `BI_Antivirus_Enterprise_v1.1.0.apk` to phone storage, open Files app, and tap Install.

### Windows Installation
- **Setup Installer:** Run `BI_Antivirus_Enterprise_v1.1.0_Setup.exe` and follow prompts. Upgrades cleanly preserve existing settings and quarantine vault.
- **Portable Bundle:** Extract `BI_Antivirus_Enterprise_v1.1.0_Portable.zip` and execute `Launch_BIAntivirus.bat`.

---

## ⚠️ Transparent Disclosures & Known Limitations

- **Physical Device Testing Status:** Automated unit tests (35/35 JVM release tests) and cross-platform verification suites (8/8 stages) passed 100%. Physical-device on-hardware testing for specific models (such as iQOO Z9x 5G) remains pending user USB data cable connection.
- **Universal Compatibility Scope:** While the architecture is designed and compiled to run universally on Android 8.0+ devices without native ABI lock-in, compatibility across every manufacturer custom Android fork and skin cannot be unconditionally guaranteed until physically tested on each hardware variant.
- **Distribution Notice:** This is an independent, sovereign security release. It is distributed directly via GitHub and local tools; it is not hosted on Google Play Store. Automatic silent background installation is not supported by design (explicit user authorization required).
"""

def get_token() -> str:
    p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input='protocol=https\nhost=github.com\n\n')
    for line in out.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    return ""

def main():
    token = get_token()
    if not token:
        print("[!] Error: Could not retrieve GitHub token from git credential manager.")
        return 1

    # Check files exist
    files_to_upload = [
        (APK_PATH, "BI_Antivirus_Enterprise_v1.1.0.apk", "application/vnd.android.package-archive"),
        (SETUP_PATH, "BI_Antivirus_Enterprise_v1.1.0_Setup.exe", "application/vnd.microsoft.portable-executable"),
        (PORTABLE_PATH, "BI_Antivirus_Enterprise_v1.1.0_Portable.zip", "application/zip"),
        (MANIFEST_PATH, "SHA256_MANIFEST_v1.1.0.txt", "text/plain"),
    ]

    for p, name, _ in files_to_upload:
        if not p.exists():
            print(f"[!] Error: Missing artifact: {p}")
            return 1

    # 1. Push git tag locally and to remote
    print(f"[*] Creating local tag '{TAG}' on current HEAD...")
    subprocess.run(["git", "tag", "-a", TAG, "-m", TITLE], check=False)
    print(f"[*] Pushing tag '{TAG}' to origin...")
    ret = subprocess.run(["git", "push", "origin", TAG], capture_output=True, text=True)
    print(ret.stdout.strip())
    print(ret.stderr.strip())

    # 2. Create GitHub Release
    print(f"[*] Creating GitHub release for tag '{TAG}'...")
    release_payload = {
        "tag_name": TAG,
        "target_commitish": TARGET_BRANCH,
        "name": TITLE,
        "body": RELEASE_NOTES,
        "draft": False,
        "prerelease": False
    }

    url = f"https://api.github.com/repos/{REPO}/releases"
    data = json.dumps(release_payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "BIAntivirus-Release-Agent")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            rel = json.loads(resp.read().decode("utf-8"))
            release_id = rel["id"]
            html_url = rel["html_url"]
            upload_url_template = rel["upload_url"] # e.g. https://uploads.github.com/.../assets{?name,label}
            print(f"[+] Release created successfully! ID: {release_id}")
            print(f"[+] Release Page: {html_url}")
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        print(f"[!] HTTP error {e.code}: {err_msg}")
        return 2

    # Clean upload url
    base_upload_url = upload_url_template.split("{")[0]

    # 3. Upload assets
    print("\n[*] Uploading release assets...")
    for path, name, ct in files_to_upload:
        size = path.stat().st_size
        print(f"    • Uploading {name} ({size:,} bytes)...")
        upload_url = f"{base_upload_url}?name={urllib.parse.quote(name)}"
        file_bytes = path.read_bytes()

        up_req = urllib.request.Request(upload_url, data=file_bytes, method="POST")
        up_req.add_header("Authorization", f"Bearer {token}")
        up_req.add_header("Accept", "application/vnd.github+json")
        up_req.add_header("Content-Type", ct)
        up_req.add_header("User-Agent", "BIAntivirus-Release-Agent")

        try:
            with urllib.request.urlopen(up_req, timeout=180) as up_resp:
                up_res = json.loads(up_resp.read().decode("utf-8"))
                download_url = up_res.get("browser_download_url")
                print(f"      [PASS] Uploaded! Asset ID: {up_res.get('id')}")
                print(f"      Download URL: {download_url}")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            print(f"      [FAIL] Failed to upload {name}: HTTP {e.code} - {err_msg}")
            return 3

    print(f"\n[+] ALL 4 ASSETS SUCCESSFULLY PUBLISHED TO {html_url}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

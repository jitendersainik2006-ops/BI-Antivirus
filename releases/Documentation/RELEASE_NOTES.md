# BI Antivirus Enterprise — Official Release Notes
### Multi-Platform Public Release: v1.0.0-enterprise (General Availability)

**Release Tag:** `v1.0.0-enterprise`  
**Engine Release:** `2026.11-RELEASE`  
**App Version:** `1.1.0-PRO`  
**Release Date:** November 2026  
**Platforms Supported:** Windows 10/11 x64, Android 8.0+ (API 26–34), iOS 15.0+ (Source-Ready)  
**Automated Regression:** 285 / 285 tests passed across 45 suites (100% pass rate)  
**Security Certification:** 0 hardcoded secrets, DPAPI & AES-256-HMAC encryption, 100% offline sovereign security  

---

## 1. Executive Summary

**BI Antivirus Enterprise** (Black Intel Cyber Defense Platform) v1.0.0-enterprise is a sovereign, multi-platform cybersecurity and endpoint defense platform. Engineered from scratch with **100% original, proprietary source code**, the platform features an executive **Black & Gold visual identity** (`#0A0B0E`, `#D4AF37`), multi-layered detection heuristics, memory exploit auditing, ransomware honeytokens, authenticated quarantine isolation, and autonomous workflow automation across desktop and mobile operating systems.

---

## 2. Release Distribution Packages & Verified Artifacts

All release packages are cryptographically hashed with SHA-256 and verified against `SHA256_MANIFEST.txt`:

| Package | Target Platform | File Name | Size | SHA-256 Checksum |
| :--- | :--- | :--- | :---: | :--- |
| **Windows Installer** | Windows 10/11 x64 | `BI_Antivirus_Enterprise_v1.0.0_Setup.exe` | 3.18 MB | `7b6d015371dffa5dd79174c28ae4f9e9d3b34b70d3c951a26cb9bd00c1e79d1c` |
| **Windows Portable** | Windows 10/11 x64 | `BI_Antivirus_Enterprise_v1.0.0_Portable.zip` | 852 KB | `8ff2db14df0ad46d40130cfde6d866ca72fe97722f757fbe5059d52bbcab4b28` |
| **Android Release APK** | Android 8.0+ | `BI_Antivirus_Enterprise_v1.0.0.apk` | 1.18 MB | `5257ce5a53ec10e5f91be7c434a0fd4e941358ed2fc0a6474f14ac006824df83` |
| **Checksum Manifest** | Universal | `SHA256_MANIFEST.txt` | 4.24 KB | Verified for all 30 release files |

---

## 3. Major Features & Capabilities in v1.0.0-enterprise

### 3.1 Executive Black & Gold Visual Identity & UX Modernization
- **Theme Standardization:** Completely overhauled the user interface with an executive Black & Gold color palette (`#0A0B0E`, `#D4AF37`, `#181A22`, `#E8C547`), modern card typography, and unified visual hierarchy.
- **First-Run Onboarding Wizard:** 4-step interactive wizard guiding new users through Real-Time Guard, USB Sentinel, Ransomware Shield, and baseline scanning.
- **Clean Navigation & Zero Dead Buttons:** All 7 primary views (Dashboard, Scan Center, Quarantine Vault, Threat History, Protection Hub, Settings, and About) are fully wired and functional.

### 3.2 Easy Windows Setup & Upgrade Resilience
- **Inno Setup 6 Installer:** 1-click silent or interactive installation (`Setup.exe /VERYSILENT`), automatic shortcut generation, and seamless uninstallation.
- **Data & Vault Retention:** Upgrades and uninstalls automatically preserve user settings (`settings.json`), threat history databases, and the encrypted quarantine vault (`.biq`).

### 3.3 Sovereign Android Application (Jetpack Compose & Material 3)
- **Native Android Architecture:** Modern Kotlin 1.9 codebase utilizing Jetpack Compose, Coroutines, StateFlow, and Material 3 design.
- **Storage Access Framework (SAF):** User-guided document tree permission model allowing comprehensive threat sweeps without requiring dangerous root access.
- **Production APK Signature Scheme v2:** Cryptographically signed using RSA-4096 key, verifying with `apksigner`.

### 3.4 Apple iOS Architecture (Source-Ready)
- **Native Swift 5.9 & SwiftUI:** Complete threat detection engine and quarantine vault implemented using Apple CryptoKit.
- **Source-Ready Deployment:** Located in `ios/`, ready for immediate compilation on macOS workstations with Xcode 15+.

### 3.5 Core Defense Engine & Autonomous Automation
- **Multi-Layer Detection:** Streaming SHA-256/MD5 hashing in 64 KB memory-safe blocks, Shannon entropy calculation ($H > 7.2$), double extension detection, and PE struct classification.
- **Memory Exploit Sentinel:** Non-invasive process mitigation checks (DEP, ASLR, CFG) and bounded `VirtualQueryEx` sweeps for unbacked RWX pages.
- **Ransomware Canary Defense:** Deploys hidden decoy files, monitors high-frequency mutation bursts ($\ge 3$ in 5s), and tracks entropy shifts.
- **Local n8n Workflow Automation:** Genuine n8n Community Edition integration on localhost with zero external cloud dependencies.

---

## 4. Test Verification & Acceptance Status

- **Windows Regression:** 285 tests across 45 suites passed with 100% success (`python run_tests.py`).
- **Cross-Platform Verification:** 8/8 pipeline stages passed (`python scripts/test_cross_platform.py`).
- **Windows Live Deployment QA:** Passed (Fresh install, upgrade, uninstall, dashboard navigation, scan, quarantine, and settings persistence).
- **Android Physical Hardware Testing:** Build and signature verified; physical device verification on iQOO Z9x 5G hardware remains pending USB debugging connection.
- **iOS Binary Status:** Source-ready in `ios/`; binary compilation pending macOS/Xcode workstation.

---

## 5. Security & Boundary Disclosures

1. **User-Space vs Kernel Minifilter Driver:** Operates in user-mode (Ring 3) via native Win32/NT APIs (`ReadDirectoryChangesW`, `CreateToolhelp32Snapshot`, `NtQueryInformationProcess`). This guarantees zero blue-screen (BSOD) risk, but interception is near-instantaneous rather than synchronous kernel pre-execution.
2. **Local Threat Catalog:** Operates on a 100% offline local signature database and local heuristic models, ensuring complete privacy with zero cloud telemetry.
3. **SmartScreen Notice:** Because this community release is distributed without a commercial EV Code Signing certificate, Windows SmartScreen may display an *"Unknown Publisher"* prompt on first launch.

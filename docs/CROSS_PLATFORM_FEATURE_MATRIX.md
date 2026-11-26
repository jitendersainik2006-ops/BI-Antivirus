# BI Antivirus Enterprise — Cross-Platform Feature Parity Matrix

## Executive Summary
BI Antivirus Enterprise is engineered with platform-appropriate security primitives across Windows, Android, and iOS. Each platform implementation leverages the maximum capabilities permitted by the underlying operating system while strictly respecting user privacy, platform security guidelines, and operating system sandboxing boundaries.

---

## 1. Comprehensive Platform Parity Table

| Security Capability | Windows 10/11 x64 | Android 8.0+ (API 26+) | iOS 16.0+ |
| :--- | :---: | :---: | :---: |
| **Language & UI Toolkit** | Python 3.12 / CustomTkinter | Kotlin / Jetpack Compose | Swift 5.9 / SwiftUI |
| **Core UI Theme** | Black Intel Black & Gold (`#0A0A0C`, `#181A22`, `#D4AF37`) | Black Intel Black & Gold (`#0A0A0C`, `#181A22`, `#D4AF37`) | Black Intel Black & Gold (`#0A0A0C`, `#181A22`, `#D4AF37`) |
| **Static Hash Engine (SHA-256)** | Native `hashlib` (Chunked) | `MessageDigest` (64 KB stream) | Apple `CryptoKit` (64 KB stream) |
| **Static Hash Engine (MD5)** | Native `hashlib` (Chunked) | `MessageDigest` (64 KB stream) | `CommonCrypto` (64 KB stream) |
| **Shannon Entropy Calculation** | High-precision Python math | High-precision Kotlin math | High-precision Swift math |
| **Entropy Packing Threshold** | $H \ge 7.2$ | $H \ge 7.2$ | $H \ge 7.2$ |
| **Heuristic Double Extension Scan** | Supported (.pdf.exe, .doc.vbs, etc.) | Supported (.pdf.apk, .jpg.apk, etc.)| Supported (.pdf.ipa, .doc.mobileconfig)|
| **Known Malware Pattern Search** | EICAR, AMSI bypass, shellcode | EICAR, Root execution strings | EICAR, Untyped Config profiles |
| **Web & Network Protection** | Web Shield & DNS reputation | `WebReputationAuditor` (Phishing / Punycode / IP) | `WebReputationAuditor` (Phishing / Punycode / IP) |
| **Privacy & Posture Protection** | Anti-telemetry, sensitive file audit | DevicePostureAuditor (PIN, Enc, Root) | iOSDevicePostureChecker (Biometrics, Lock) |
| **Signature Catalog Format** | SQLite + In-Memory Index | JSON (`mobile_threat_signatures`) | JSON (`mobile_threat_signatures`) |
| **Shared JSON Validation Schemas** | 6 schemas (catalog, report, posture, config, policy, update) | 6 schemas verified | 6 schemas verified |
| **Filesystem Access Scope** | Entire volume / Full system drive | Storage Access Framework (SAF) | Document Picker (Security-Scoped) |
| **Real-Time On-Access Scanning** | Supported (Watchdog / Win32 API) | Not available (OS Scoped Storage) | Not available (Apple App Sandbox) |
| **Process / Memory Inspection** | Supported (Win32 / PSUtil APIs) | Restricted (Linux `ptrace` blocked) | Restricted (iOS sandboxed) |
| **Threat Isolation / Quarantine** | AES-256 Authenticated Vault (`data/quarantine`) | AES-256-GCM (`filesDir/quarantine`, 12B nonce, 128b tag) | CryptoKit AES.GCM (`QuarantineVault`, 12B nonce, 128b tag) |
| **Security Posture Auditing** | Windows Defender, UAC, Firewall | Lock PIN, Hardware Enc, ADB, Patch | Passcode, Biometrics, iOS Version |
| **Local Audit & History Log** | SQLite (`scan_history.db`) | SQLite (`bi_scan_history.db`) | Sandboxed JSON (`history.json`) |
| **Network / Cloud Webhook Alerts** | n8n enterprise integration | REST/Webhook ready | REST/Webhook ready |
| **Host Privilege Requirement** | Standard user / Optional admin | Standard user (Zero root) | Standard user (Zero jailbreak) |

---

## 2. Core Detection Logic & Explicit Scan Verdicts

All three platforms share synchronized mathematical formulas, heuristic rules, and explicit 5-state verdict classifications:

### Explicit Result Classifications
1. **`CLEAN`**: Benign payload verified against all signature catalogs and heuristic analyzers.
2. **`THREAT_DETECTED`**: Definitive match against known malware signatures (SHA-256/MD5) or standard EICAR test vectors.
3. **`SUSPICIOUS`**: Anomaly detection triggered (spoofed magic bytes, executable masquerading, suspicious double extensions, or packed high entropy).
4. **`UNSUPPORTED`**: File format is outside supported inspection formats for the mobile endpoint (e.g., `.xyz`). **Guaranteed never reported as `CLEAN`**.
5. **`SCAN_ERROR`**: File stream is corrupted, truncated, empty, or structurally unparseable. **Guaranteed never reported as `CLEAN`**.

### Core Heuristic & Mathematical Alignment
1. **Hash Verification:**
   - Case-insensitive comparison against SHA-256 (64 hex characters) and MD5 (32 hex characters).
   - Instant $O(1)$ lookups via synchronized signature catalogs.
2. **Shannon Entropy Formula:**
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   - Files with $H \ge 7.2$ and size $> 1024$ bytes trigger `HEUR:HIGH_SHANNON_ENTROPY`.
3. **Magic Byte Header Analysis:**
   - Evaluates true binary headers against declared file extensions (e.g. PK zip/APK headers masquerading as `.jpg`, Mach-O/ELF binaries disguised as `.pdf`).
4. **Double Extension Rules:**
   - Detects hidden payloads masquerading as benign media or office documents.
5. **Unified Severity Levels:**
   - `CRITICAL`: Known active malware signature or verified test payload.
   - `HIGH`: Multiple heuristic indicators or spoofed executable header.
   - `MEDIUM`: Single heuristic anomaly (e.g., suspicious double extension).
   - `LOW`: Mild informational deviation or scan error.
   - `NONE`: Verified clean or unsupported item.

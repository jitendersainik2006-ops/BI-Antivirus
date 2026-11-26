# BI Antivirus Enterprise — Operating System Boundaries & Technical Limitations

## Introduction
Security applications must communicate their operating boundaries with total technical honesty. Modern mobile operating systems (Android and iOS) enforce strict process sandboxing and security architectures that differ substantially from traditional desktop platforms like Windows.

This document details the exact technical boundaries and architectural constraints of BI Antivirus Enterprise on each supported platform.

---

## 1. Android Technical Boundaries (API Level 26–34)

### 1.1 Scoped Storage & Storage Access Framework (SAF)
- **Constraint:** Starting in Android 10 (API 29) and enforced in Android 11+ (API 30+), Google introduced Scoped Storage. Applications can no longer scan the entire internal storage (`/sdcard` or `/data`) without special user consent.
- **Implementation:** BI Antivirus utilizes the Android Storage Access Framework (`ACTION_OPEN_DOCUMENT`). Users select the specific file or tree they wish to scan.
- **Limitation:** The app cannot silently crawl the entire filesystem in the background without user interaction.

### 1.2 Inter-Process Memory Inspection
- **Constraint:** Android's Linux kernel enforces strict process isolation (`SELinux`). Third-party apps cannot attach to other running processes (`ptrace` is denied by SELinux policy).
- **Limitation:** Memory scraping and live RAM injection detection across third-party apps is prohibited on non-rooted devices.

### 1.3 System-Wide Network Inspection
- **Constraint:** On Android, intercepting network traffic across all apps requires either a local VPN service (`VpnService`) or system CA certificate installation with user approval.
- **Limitation:** BI Antivirus does not inspect cleartext HTTPS traffic from other applications out of respect for user privacy and platform integrity.

---

## 2. iOS Technical Boundaries (iOS 16+)

### 2.1 Apple App Sandbox (`sandbox_init`)
- **Constraint:** Apple's App Sandbox strictly confines each third-party app to its own container directory (`/var/mobile/Containers/Data/Application/<UUID>/`).
- **Implementation:** File inspection is performed via `UIDocumentPickerViewController` with security-scoped URLs. When the user selects a file from the Files app (iCloud, Downloads, or local storage), iOS temporarily grants scoped read access.
- **Limitation:** An iOS antivirus cannot scan other installed apps' private sandbox storage, nor can it inspect the root filesystem (`/`) or system binaries.

### 2.2 Background Execution & Daemon Restrictions
- **Constraint:** iOS does not permit third-party applications to run continuous, unrestricted background daemons. Background execution is strictly limited to specific modes (audio, location, VoIP, background fetch).
- **Limitation:** Continuous 24/7 on-access real-time file monitoring is impossible within standard App Store / TestFlight guidelines without an Enterprise MDM Supervised profile and Network Extension framework.

### 2.3 Biometrics and Hardware Enclave Access
- **Constraint:** Apple's Secure Enclave processes biometric data (Face ID / Touch ID) in dedicated hardware. Third-party apps only receive boolean authorization status via `LAContext`.
- **Limitation:** BI Antivirus evaluates whether biometrics and device passcode are configured; it cannot access biometric templates.

---

## 3. Windows Technical Boundaries (Windows 10/11 x64)

### 3.1 Kernel Mode Drivers vs. User-Mode Antivirus
- **Constraint:** BI Antivirus Enterprise on Windows operates as an advanced user-mode application. It does not load proprietary kernel-mode filesystem filter drivers (`ELAM` - Early Launch Anti-Malware).
- **Parity Note:** Real-time protection is achieved via user-mode Win32 directory change notifications (`ReadDirectoryChangesW` / `watchdog`), which provides high-speed scanning without risking kernel BSODs or destabilizing the operating system.

---

## 4. Summary Matrix of Platform Boundaries

| Boundary / Capability | Windows | Android | iOS |
| :--- | :---: | :---: | :---: |
| Full Filesystem Crawl | **Permitted** (Full disk access) | **Restricted** (SAF picker required) | **Restricted** (Document picker only) |
| Inter-Process Memory Scanning | **Permitted** (OpenProcess/ReadProcessMemory)| **Blocked** (Linux SELinux) | **Blocked** (App Sandbox) |
| Background Daemon | **Permitted** (Windows Service/Process) | **Restricted** (WorkManager/Foreground)| **Blocked** (OS Background execution rules)|
| Kernel-Level Driver Required | **No** (Safe user-mode architecture) | **No** (Standard user-space) | **No** (Standard sandboxed app) |
| Jailbreak / Root Requirement | **None** | **None** | **None** |

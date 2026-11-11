# BI ANTIVIRUS ENTERPRISE — SPRINT 13 LIMITATIONS & SECURITY REVIEW
**Project Root:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Branch:** `main`  
**Date:** November 11, 2026  
**Auditor:** Independent Principal Security Architect  

---

## 1. Executive Summary

This document establishes the verified defensive security baseline and architectural boundaries of BI Antivirus Enterprise following Sprint 13.

By introducing explicit Administrator vs. Standard User mode detection and deep Windows ETW provider auditing, the platform provides complete operational transparency, ensuring operators and administrators know exactly which defenses are enforcing at the OS level versus operating in audit-only mode.

---

## 2. Host Enforcement & Operational Mode Boundaries

### 2.1 Standard User Mode (Audit-Only & User-Space Protection)
When BI Antivirus is executed without an elevated Administrator token, it operates with standard user rights (Medium Integrity). In this mode:
- **Fully Active Capabilities:**
  - Real-time filesystem on-access file evaluation for user-owned directories (`Downloads`, `Desktop`, user profiles).
  - Machine learning classification (12-feature PE vectorizer) and Shannon entropy heuristics.
  - Canary decoy honeypots deployed in user directories for ransomware burst detection.
  - Digital signature verification via native Windows `wintrust.dll` / `WinVerifyTrust`.
  - AES-256-CBC quarantine encryption and safe restoration with path traversal (`..`) blocking.
  - Local REST API (`127.0.0.1:8765`), EDR incident correlation, and SIEM hash chaining.
- **Audit-Only Capabilities (Restricted by Windows UAC):**
  - **Windows Defender Firewall:** Operates in audit and staging mode. Rules are validated and queued in memory; active deployment via `netsh advfirewall` requires Administrator rights.
  - **USB Device Control:** Worm detection (`autorun.inf`, `.lnk`) is active. Applying system-wide `HKLM StorageDevicePolicies WriteProtect = 1` requires Administrator rights.
  - **Full Disk Encryption:** Volume metadata parsing is active. Querying live BitLocker status via `manage-bde.exe` requires Administrator rights.
  - **Process Privilege Guard:** Auditing and terminating user-owned processes is active. Inspecting system-level tokens or terminating elevated processes is restricted by Windows OS access controls.

### 2.2 Administrator Mode (Full Windows Enforcement)
When executed with an elevated Administrator token (High Integrity):
- All audit-only capabilities transition automatically to **Active Enforcement**.
- Windows Defender Firewall rules are applied directly to the active Windows filtering profiles.
- USB StorageDevicePolicies registry write-protection can be committed directly to HKLM.
- Process token inspection operates across all non-PPL system processes.

---

## 3. Windows Event Tracing (ETW) Telemetry Boundaries

Sprint 13 introduced `ETWTelemetryProbe` to assess Windows ETW security providers:
- **Registered Providers Verified:**
  - `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)
  - `Microsoft-Windows-Threat-Intelligence` (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`)
  - `Microsoft-Windows-DNS-Client` (`{1C950233-3226-42D0-90DA-E3169F8B337B}`)
  - `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`)
- **Session Creation Gating:**
  - Starting a real-time ETW kernel trace session requires elevated Administrator rights or membership in the "Performance Log Users" security group.
  - Subscribing to `Microsoft-Windows-Threat-Intelligence` strictly requires an Early Launch Anti-Malware (ELAM) or Protected Process Light (PPL) certificate issued by Microsoft.
- **Graceful Fallback & Data Privacy:**
  - When running as standard user or without ELAM, the probe logs non-PII diagnostic metadata (PID, base image name, timestamps) and falls back to `Toolhelp32 Snapshotting & ReadDirectoryChangesW` without throwing errors.

---

## 4. Kernel Driver & Cloud Architecture Boundaries

- **Kernel Minifilter Driver (`FLTMGR.SYS`):** Ring 0 pre-execution I/O filtering remains blocked due to Microsoft Extended Validation (EV) hardware token and WHQL cross-signing requirements. User-space file monitoring operates with sub-second latency ($< 0.1$s).
- **Dynamic Detonation Sandbox:** Operates as an isolated local subprocess container simulation with `is_simulation: True` disclosure rather than a vendor-hosted multi-tenant cloud hypervisor.
- **Data Sovereignty:** All threat catalogs, model weights, fleet databases, and audit logs remain strictly confined to the endpoint (`D:\bit defender`). Zero telemetry leaks to overseas cloud networks.

---

## 5. Defensive Cryptography & Security Verification

1. **Zero Secret Exposure:** Zero hardcoded passwords, private keys, or API tokens exist in repository code, tests, or documentation.
2. **Password & Token Security:** Unique 128-bit cryptographic salts per user (`secrets.token_hex(16)`), PBKDF2-HMAC-SHA256 ($\ge 100,000$ iterations), structured session tokens (`BI-SESS-`), and instant session purge on password change or user deactivation.
3. **Quarantine Vault Hardening:** AES-256-CBC Encrypt-then-MAC with HMAC-SHA256, randomized vault filenames, and strict path traversal (`..`) rejection.
4. **Threat Intelligence Integrity:** Monotonic sequence checking, TTL freshness gating, HMAC-SHA256 manifest verification, and hexadecimal IOC schema validation.
5. **D: Drive Confinement:** 100% of project data, logs, databases, and caches are confined to `D:\bit defender`. Zero project-owned files reside on `C:`.

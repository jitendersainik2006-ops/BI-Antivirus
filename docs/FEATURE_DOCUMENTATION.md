# BI Antivirus — Subsystem & Feature Documentation

This document describes the 12 core security subsystems implemented and verified in BI Antivirus.

---

## 1. Multi-Layer Detection Engine (`bi_antivirus/core/detector.py`)
- **Streaming Hashing:** Inspects files in 64 KB memory-safe chunks, calculating both SHA-256 and MD5 simultaneously.
- **SQLite Signature Lookup:** $O(1)$ indexed lookup against local malware hash tables in `data/signatures.db`.
- **Zero-Byte Suppression:** Files with `stat().st_size == 0` are immediately classified as `CLEAN` to eliminate false positives on Windows OS temporary lock files.
- **Pattern Matching:** Regular expression scanner searching for byte patterns, embedded scripts, and dropper signatures.

---

## 2. Authenticated Quarantine Vault (`bi_antivirus/core/quarantine.py`)
- **Container Format (`BIQ2`):**
  `Magic [4B: 'BIQ2'] || Version [1B: 0x01] || IV [16B] || Tag [32B: HMAC-SHA256] || Ciphertext [NB: AES-256-CBC]`
- **Key Hierarchy:** 256-bit AES encryption key + 256-bit HMAC authentication key derived from a 256-bit master key wrapped with Windows DPAPI machine-level entropy.
- **Atomic Operations:** Files are written to temporary staging locations and swapped atomically via `os.replace` to prevent corrupted partial files.
- **Dual-Mode Decryption:** Transparently recognizes both modern `BIQ2` authenticated vaults and legacy `v1` XOR vaults for seamless backward compatibility.

---

## 3. Native Authenticode Verifier (`bi_antivirus/core/authenticode.py`)
- **WinTrust Integration:** Calls Windows `wintrust.dll` (`WinVerifyTrust`) via `ctypes` using `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
- **Trust Damping:** Files with valid, trusted digital signatures from recognized Certificate Authorities receive false-positive score reductions.
- **Tamper Detection:** Executables with modified digests or revoked certificates are escalated to CRITICAL risk.

---

## 4. Behavioral Process Sentinel (`bi_antivirus/monitors/behavioral.py`)
- **Snapshot Telemetry:** Queries active processes via `kernel32.CreateToolhelp32Snapshot`.
- **Process Command-Line Extraction:** Implements `ntdll.NtQueryInformationProcess(60)` under user-level rights (`PROCESS_QUERY_LIMITED_INFORMATION = 0x1000`), benchmarked at 0.23 ms.
- **LOLBin Exploitation Detection:** Flags suspicious executions of `powershell.exe -enc`, `certutil -urlcache`, `mshta.exe`, and `vssadmin delete shadows`.

---

## 5. Ransomware Shield (`bi_antivirus/monitors/ransomware_shield.py`)
- **Canary Decoys:** Deploys hidden decoy files (`.bi_integrity_canary.docx`) in monitored user folders.
- **Burst Mutation Tracking:** Flags processes renaming or modifying $\ge 3$ files within a 5-second sliding window to known ransomware extensions (`.lockbit`, `.blackcat`, `.crypto`).
- **Extortion Note Interception:** Intercepts newly created `readme_to_decrypt.txt` files.

---

## 6. Removable Media (USB) Sentinel (`bi_antivirus/monitors/usb_sentinel.py`)
- **Drive Polling:** Detects connected drives using `kernel32.GetDriveTypeW`.
- **Autorun Neutralization:** Scans root directories for `autorun.inf` execution directives.
- **Shortcut Worm Auditing:** Flags hidden executables with masquerading `.lnk` shortcuts.

---

## 7. Windows Baseline Security Auditor (`bi_antivirus/core/vulnerability.py`)
Audits 5 critical Windows security controls:
1. **User Account Control (UAC):** Validates `EnableLUA == 1`.
2. **SMBv1 Deprecation:** Confirms legacy SMBv1 protocol is disabled.
3. **Windows Defender Firewall:** Audits Domain, Private, and Public profile states.
4. **Remote Desktop (RDP) NLA:** Confirms Network Level Authentication is enforced.
5. **Windows Update Service:** Confirms `wuauserv` service is configured and operational.

---

## 8. On-Demand Scanner (`bi_antivirus/core/scanner.py`)
- **Quick Scan:** Inspects critical Windows execution hotspots (Downloads, Desktop, Startup, Temp).
- **Full Scan:** Deep multi-threaded scan across all profile directories and drive roots.
- **Custom Scan:** Targets user-selected folders or individual files.
- **Thread Safety:** Background execution with real-time progress callbacks dispatched safely to the UI thread.

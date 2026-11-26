# BI Antivirus Enterprise — Windows Verification & Setup Guide

## Overview
**BI Antivirus Enterprise for Windows** is a native endpoint protection and threat detection application engineered for Windows 10 and 11 (x64). It features high-speed heuristic scanning, multi-threaded signature matching, real-time directory watchdog monitoring, PE file anomaly analysis, memory-based threat pattern matching, and an isolated encrypted quarantine vault.

---

## 1. System Requirements & Prerequisites

| Requirement | Specification |
| :--- | :--- |
| **Operating System** | Windows 10 (64-bit) or Windows 11 (64-bit) |
| **Processor Architecture** | x64 (AMD64 / Intel 64) |
| **Python Runtime** | Python 3.10, 3.11, or 3.12 (64-bit) |
| **RAM** | Minimum 4 GB (8 GB recommended) |
| **Disk Space** | 250 MB free space on `D:` drive |
| **User Privileges** | Standard User (Administrator not required for scanning) |

---

## 2. Directory Layout

The canonical installation directory is:
```text
D:\bit defender\
├── bi_antivirus/             # Core Python security engines and GUI
│   ├── core/                 # Scanner, detector, and heuristic logic
│   ├── database/             # SQLite signature store and cache
│   ├── gui/                  # CustomTkinter Black & Gold desktop interface
│   ├── quarantine/           # AES-256 encrypted vault implementation
│   ├── realtime/             # Directory watchdog and event monitor
│   └── tests/                # 44 test suites (276 tests)
├── data/                     # Signatures database and quarantine vault
├── docs/                     # Setup, architecture, and feature documentation
├── scripts/                  # Cross-platform test runner and build tools
├── shared/                   # Cross-platform signatures, schemas, test vectors
├── launch_gui.py             # Desktop GUI launcher
└── run_tests.py              # Automated 276-test validation runner
```

---

## 3. Independent Verification Instructions for Sir

Sir can independently verify the health and integrity of BI Antivirus on any Windows system using the following steps:

### Step 1: Open PowerShell or Command Prompt
Navigate to the project root on `D:` drive:
```powershell
cd "D:\bit defender"
```

### Step 2: Run the Comprehensive Windows Automated Test Suite
Execute the verified test runner to run all 276 automated unit and integration tests across 44 suites:
```powershell
python run_tests.py
```
**Expected Output:**
```text
======================================================================
      BI ANTIVIRUS - AUTOMATED VALIDATION TEST SUITE
======================================================================
...
Ran 276 tests in ~95s
OK
Overall Status: SUCCESS (ALL TESTS PASSED)
======================================================================
```

### Step 3: Run the 8-Stage Cross-Platform Verification Suite
Verify shared signature synchronization, schemas, test vectors, and mobile architectures:
```powershell
python scripts/test_cross_platform.py
```
**Expected Output:**
```text
===========================================================================
BI ANTIVIRUS ENTERPRISE - COMPREHENSIVE CROSS-PLATFORM VERIFICATION SUITE
Platforms: Windows 10/11 x64 | Android (API 26-34) | iOS (16.0+)
===========================================================================
[1/8] Verifying Shared Threat Signatures Parity...
[2/8] Validating Shared JSON Schemas...
[3/8] Testing Test Vectors Against Mobile Detection Engine...
[4/8] Testing Magic Byte Header and Extension Spoofing Detection...
[5/8] Testing Quarantine Cryptographic Integrity & Overwrite Safety...
[6/8] Auditing Android Native Architecture and Codebase...
[7/8] Auditing iOS Native Architecture and Codebase...
[8/8] Executing Windows Baseline Regression Test (276 Tests)...
===========================================================================
ALL 8 VERIFICATION AND REGRESSION STAGES PASSED (100% SUCCESS)!
===========================================================================
```

### Step 4: Launch the Desktop Graphical Interface
Launch the interactive Black & Gold desktop security center:
```powershell
python launch_gui.py
```
- Verify the **System Security Status** displays **Protected** with Cyber Dark & Gold aesthetics.
- Execute a **Quick Scan** or **Custom File Scan** against `shared/test_vectors/`.
- Review the **Quarantine Vault** and **Scan History**.

---

## 4. Safe Test Vectors for Verification

All testing should be conducted strictly with the harmless test vectors located in `shared/test_vectors/`:

1. `clean_document.txt`: Harmless text file. (Expected: `CLEAN`)
2. `suspicious_double_extension.pdf.apk`: Double extension simulation. (Expected: `SUSPICIOUS`)
3. `high_entropy_packed_sample.bin`: High Shannon entropy ($H \ge 7.2$). (Expected: `SUSPICIOUS`)
4. `corrupted_truncated_sample.bin`: Truncated input. (Expected: Handled safely)
5. `unsupported_format.xyz`: Arbitrary format. (Expected: Handled safely)

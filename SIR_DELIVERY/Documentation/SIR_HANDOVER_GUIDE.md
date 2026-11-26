# BI ANTIVIRUS ENTERPRISE — SIR HANDOVER & EVALUATION GUIDE

**Project:** BI Antivirus Enterprise  
**Target Recipient:** Respected Sir  
**Canonical Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Distribution Archive:** `dist\BI_Antivirus_Enterprise_v1.0.0_Portable.zip`  
**Archive SHA-256:** `8ff2db14df0ad46d40130cfde6d866ca72fe97722f757fbe5059d52bbcab4b28`  
**Date of Handover:** November 12, 2026  

---

## 1. Executive Summary for Sir

Respected Sir,

BI Antivirus Enterprise is a modular, high-performance Windows desktop antivirus and endpoint detection platform engineered from the ground up with 100% original Python and Win32 architecture. It provides layered threat detection, an authenticated AES-256 quarantine vault, behavioral process monitoring, removable media (USB) protection, host firewall management, memory exploit auditing, and enterprise EDR incident graph correlation.

This handover package is structured so that you can independently verify, install, run, and evaluate the complete system on any Windows 10 or Windows 11 (64-bit) computer.

---

## 2. Evaluation Options

You have two simple ways to evaluate the platform:

### Option A: Portable Standalone Archive (Recommended)
Download and extract the verified portable distribution bundle:
* **File:** `dist\BI_Antivirus_Enterprise_v1.0.0_Portable.zip`
* **Size:** ~0.81 MB (278 files)
* **SHA-256 Checksum:** `8ff2db14df0ad46d40130cfde6d866ca72fe97722f757fbe5059d52bbcab4b28`
* Contains all verified engine components, desktop GUI, test suites, documentation, and one-click `.bat` launchers.
* Excludes internal developer maintenance utilities (`rotate_and_import_credential.py`), local databases, logs, and caches.

### Option B: Clone via Git
```powershell
git clone https://github.com/jitendersainik2006-ops/BI-Antivirus.git
cd BI-Antivirus
```

---

## 3. System Requirements & Prerequisites

| Component | Requirement | Necessity | Notes |
| :--- | :--- | :---: | :--- |
| **Operating System** | Windows 10 / Windows 11 (64-bit) | **Required** | Standard user or Administrator permissions. |
| **Python Runtime** | Python 3.12 (64-bit) | **Required** | Specifically verified on Python 3.12.10. Install from python.org with "Add python.exe to PATH" checked. |
| **Dependencies** | `requirements.txt` (`psutil>=5.9.0`) | **Required** | Core engine runs natively using standard library + Win32 `ctypes`. |
| **Node.js & n8n** | Node.js v20+ / v24+ & n8n Community Edition | **OPTIONAL** | **Not required for antivirus protection, scans, GUI, quarantine, or tests.** Only needed if evaluating n8n workflow integration. |

---

## 4. Step-by-Step Hands-on Evaluation Procedure

All commands should be executed from the extracted root folder:

### Step 1: Install Dependencies
Open PowerShell or Command Prompt in the extracted folder and run:
```powershell
pip install -r requirements.txt
```

### Step 2: Run Setup Wizard
Initialize local directories, SQLite stores, and seed signature catalogs:
```powershell
.\setup_windows.bat
# Or alternatively: python scripts\install_windows.py
```
*Verification:* Checks Python version, seeds 18 test threat signatures, and initializes WAL databases.

### Step 3: Launch Desktop GUI Dashboard
```powershell
.\run_gui.bat
# Or alternatively: python main.py
```
*Verification:* The Cyber Dark theme Tkinter desktop dashboard will open with 13 functional navigation views:
1. Overview & Health Status
2. Threat Scanner (Quick, Full, Custom)
3. Authenticated Quarantine Vault
4. Real-time Protection Monitor
5. Behavioral Process Sentinel
6. Defensive Memory Exploit Shield
7. Removable Media (USB) Sentinel
8. Firewall & Isolation Manager
9. Full Disk Encryption (BitLocker) Sentinel
10. EDR Incident Graph Forensics
11. Vulnerability & Baseline Posture
12. Threat Intelligence Updater
13. Enterprise Settings & SIEM Forwarding

### Step 4: Run Safe Harmless Live Demonstration
```powershell
.\run_demo.bat
# Or alternatively: python scripts\demo_full_lifecycle.py
```
*Verification:* Executes a 10-stage synthetic threat detection, quarantine, EDR correlation, and reporting sequence. Zero live malware is executed; zero network connections are cut.

### Step 5: Execute Automated Validation Test Suite
```powershell
.\run_tests.bat
# Or alternatively: python run_tests.py
```
*Verification:* Runs all **276 automated unit tests across 44 test suites**. Expected result: `SUCCESS (ALL TESTS PASSED)` in ~100 seconds.

### Step 6: Execute Clean-Slate Acceptance Test
```powershell
python scripts\verify_clean_acceptance.py
```
*Verification:* Proves end-to-end functionality from a clean slate in an isolated local directory (`data\clean_acceptance_test`). Tests 7 acceptance gates (directory tree, SQLite WAL, threat detection, AES-256 quarantine & restore, XDR graph, vulnerability audit, clean teardown).

### Step 7: Safe Uninstallation & Data Preservation
```powershell
.\uninstall_windows.bat
```
*Verification:* Provides an interactive choice to perform a Standard Uninstall (safely preserving scan history and quarantine records) or a Complete Purge.

---

## 5. Realistic Commercial Parity Boundaries

To maintain strict scientific and professional integrity:
1. **User-Space vs Kernel Driver:** BI Antivirus operates in Windows user-space (ring 3) using Win32 `ReadDirectoryChangesW` and Toolhelp32 snapshotting. It does not load a Windows Kernel Mini-Filter Driver (`FLTMGR`). Detection is near-instantaneous rather than preemptive kernel I/O blocking.
2. **Offline Local Intelligence vs Commercial Cloud:** Threat detection relies on offline SQLite signatures, entropy math, and local heuristic rules. It does not query a live multi-billion sample commercial threat cloud.
3. **Unsigned Evaluation Bundle:** The distribution ZIP is unsigned. Windows SmartScreen may display an unknown-publisher warning on a clean machine. Production deployment would require an Authenticode EV certificate.
4. **Parity Rating:** BI Antivirus achieves **24 out of 30 capabilities** in sovereign user-space, with 6 capabilities operating under documented sovereign fallbacks. It is a demonstrable working security management platform, not a certified commercial antivirus product.

# BI ANTIVIRUS ENTERPRISE — START HERE (SIR_README_FIRST)

**Welcome Respected Sir,**

This delivery folder contains the verified portable distribution and comprehensive handover documentation for **BI Antivirus Enterprise (v1.0.0)**.

Every component in this package has been built, tested, and audited to allow you to evaluate the platform independently on any Windows 10 or Windows 11 (64-bit) computer.

---

## 1. What is BI Antivirus Enterprise?

BI Antivirus Enterprise is a modular, high-performance endpoint security platform developed with 100% original Python 3.12 and Win32 architecture. It provides:

* **Multi-Layered Threat Engine:** Hash lookup (MD5/SHA-256), byte pattern matching, PE header parsing, and Shannon entropy analysis.
* **Real-time File System Sentinel:** Multi-threaded directory watcher powered by Win32 `ReadDirectoryChangesW`.
* **Behavioral Heuristic Engine:** Live process monitoring tracking rapid file mutations, shadow copy tampering, and suspicious child process spawning.
* **Process Memory Scanner:** Win32 Toolhelp32 API process inspection detecting injected shellcode patterns, hollowed processes, and RWX memory anomalies.
* **Removable Media (USB) Sentinel:** Real-time USB drive attachment detection, volume inspection, and automated autorun/payload neutralisation.
* **Network & Firewall Isolation:** Host-level network defense using Windows Netsh / Advanced Firewall integration and single-click network isolation.
* **Full Disk Encryption Sentinel:** Audit and tracking of BitLocker volume encryption status and key protectors.
* **Vulnerability & Baseline Posture:** Automated Windows configuration assessment auditing UAC status, Windows Defender, firewall state, and OS build patch levels.
* **Enterprise Quarantine Vault:** Authenticated AES-256 encrypted isolation vault with tamper-evident metadata and atomic safe-restore capabilities.
* **EDR Incident Graph & Forensics:** Automated attack chain correlation linking processes, parent PIDs, compromised files, and MITRE ATT&CK tactics.
* **Modern Desktop GUI:** Cyber Dark theme Tkinter desktop dashboard featuring 13 functional operational views with real-time health telemetry.

---

## 2. Quick Start Guide: 8 Steps from Fresh Download to Running

### Step 1: Extract the Portable Archive
Extract `BI_Antivirus_Enterprise_v1.0.0_Portable.zip` into any folder on your computer (e.g., `D:\BI_Antivirus` or `C:\BI_Antivirus`).

### Step 2: Verify Python 3.12 (64-bit)
Ensure Python 3.12 (64-bit) is installed on your system.
* During installation, ensure **"Add python.exe to PATH"** is checked.
* Test by opening PowerShell or Command Prompt and running:
  ```powershell
  python --version
  ```
  *(Expected: `Python 3.12.x`)*

### Step 3: Install Required Dependencies
Open PowerShell or Command Prompt in the extracted folder and run:
```powershell
pip install -r requirements.txt
```
*Note: The core engine only requires `psutil>=5.9.0` — all other components rely exclusively on the Python standard library and native Windows APIs.*

### Step 4: Run the One-Click Setup Script
```powershell
.\setup_windows.bat
```
*(Or alternatively: `python scripts\install_windows.py`)*  
* **What this does:** Verifies Python runtime, creates required data directories (`data/`, `logs/`, `quarantine/`, `reports/`), initializes the threat signature database (`signatures.db`), seeds 18 built-in detection rules, enables SQLite Write-Ahead Logging (WAL), and confirms database integrity (`PRAGMA integrity_check: ok`).

### Step 5: Launch the Desktop GUI Dashboard
```powershell
.\run_gui.bat
```
*(Or alternatively: `python main.py`)*  
* **What this does:** Launches the complete Cyber Dark desktop interface with 13 functional navigation views: Overview Dashboard, Threat Scanner, Quarantine Vault, Real-time Monitor, Behavioral Sentinel, Memory Shield, USB Sentinel, Firewall & Isolation, BitLocker Sentinel, EDR Forensics Graph, Vulnerability Posture, Threat Intel, and Enterprise Settings.

### Step 6: Run the Harmless Live Demonstration
```powershell
.\run_demo.bat
```
*(Or alternatively: `python scripts\demo_full_lifecycle.py`)*  
* **What this does:** Executes a complete 10-stage synthetic threat detection, quarantine, EDR correlation, and reporting lifecycle.  
* **Safety Guarantee:** Zero actual malware is executed; zero network connectivity is interrupted; all test files are synthetic and cleaned up automatically.

### Step 7: Run the Full Automated Test Suite
```powershell
.\run_tests.bat
```
*(Or alternatively: `python run_tests.py`)*  
* **What this does:** Runs the exhaustive test suite verifying all modules:  
  **276 / 276 tests pass** across 44 test suites with 0 failures, 0 errors, and 0 skipped.

### Step 8: Safe Uninstallation Verification
```powershell
.\uninstall_windows.bat
```
* **What this does:** Demonstrates clean, safe uninstallation. Gives you the interactive option to perform a **Standard Uninstall** (preserves scan history and quarantine) or a **Complete Purge** without leaving orphaned services or registry hooks.

---

## 3. Note on Node.js and n8n

**Node.js and n8n are completely OPTIONAL workflow extensions.**
* They are **NOT** required for any core antivirus functionality: file scanning, real-time file monitoring, behavioral heuristics, process memory scanning, USB detection, quarantine, GUI dashboard, or running all 276 unit tests.
* The entire core antivirus platform runs natively on standard Python 3.12 with `psutil`.
* Node.js / n8n are only referenced if you choose to explore automated SOAR workflow orchestration via the optional webhook bridge in `scripts/n8n/`.

---

## 4. Honest Statement of Technical Boundaries & Limitations

To maintain the highest standard of scientific integrity and transparency:

1. **User-Space (Ring 3) Architecture:** BI Antivirus operates in Windows user-space using Win32 `ReadDirectoryChangesW`, Toolhelp32 snapshots, and Netsh APIs. It does **not** install a Windows Kernel Mini-Filter Driver (`FLTMGR.SYS`). File I/O interception is near-instantaneous upon file write rather than pre-execution kernel blocking.
2. **Offline Local Threat Intelligence:** The engine uses local SQLite signatures, SHA-256 lookups, entropy mathematics, and behavioral heuristic rules. It does not connect to a multi-billion sample commercial threat cloud (such as Bitdefender Global Protective Network or commercial sandbox clouds), which require paid commercial subscription infrastructure.
3. **Unsigned Evaluation Bundle:** The distribution ZIP is not code-signed with a commercial Microsoft Authenticode Extended Validation (EV) certificate. When launching executables or scripts on a clean Windows machine, Windows SmartScreen may show a blue prompt (*"Windows protected your PC"*). Click **"More info"** and then **"Run anyway"** to proceed.
4. **Commercial Parity Assessment:** BI Antivirus achieves **24 out of 30 capabilities** compared with Bitdefender GravityZone at native sovereign user-space implementation, with the remaining 6 capabilities operating under documented sovereign fallbacks (e.g., Windows Netsh firewall instead of custom NDIS filter driver). It is an evaluation and demonstration platform, not a certified commercial AV product.

---

## 5. Handover Documentation Inventory

The `Documentation\` folder contains 5 detailed reference documents for your evaluation:

| Document | Purpose |
| :--- | :--- |
| **`Documentation\SIR_HANDOVER_GUIDE.md`** | Complete master evaluation guide with system requirements, CLI options, and architecture overview. |
| **`Documentation\FRESH_WINDOWS_INSTALLATION_CHECKLIST.md`** | Step-by-step verification checklist for validating on a fresh Windows 10/11 system. |
| **`Documentation\PORTABLE_PACKAGE_AUDIT.md`** | Comprehensive packaging audit detailing file structure, exclusions, and integrity checks. |
| **`Documentation\FINAL_RELEASE_STATUS.md`** | Executive release status summary detailing test results, component status, and verification metrics. |
| **`Documentation\FINAL_PRE_PUBLICATION_REVIEW.md`** | In-depth pre-publication technical review and Bitdefender GravityZone parity gap analysis. |

---

## 6. Verification & Checksum Reference

All files in this delivery folder can be independently verified against `DELIVERY_SHA256.txt` using PowerShell:
```powershell
Get-FileHash -Algorithm SHA256 "BI_Antivirus_Enterprise_v1.0.0_Portable.zip"
```
**Expected Hash:** `8ff2db14df0ad46d40130cfde6d866ca72fe97722f757fbe5059d52bbcab4b28`

Thank you for reviewing BI Antivirus Enterprise.

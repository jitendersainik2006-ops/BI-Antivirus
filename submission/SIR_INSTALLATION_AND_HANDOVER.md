# BI ANTIVIRUS ENTERPRISE — SIR'S INSTALLATION & EXECUTIVE HANDOVER GUIDE

**Product:** BI Antivirus Enterprise — Sovereign Windows Defensive Threat Protection Platform  
**Target Platform:** Windows 10, Windows 11, Windows Server 2019+ (x64 Architecture)  
**Submission Date:** November 12, 2026  
**Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Branch:** `main`  
**Current Baseline Commit:** `f59450df8ce123fd2804222244ee27ab2f06e697`  
**Distribution Package:** `D:\bit defender\dist\BI_Antivirus_Enterprise_v1.0.0_Portable.zip` (0.46 MB, 172 files)  

---

## RESPECED SIR: WELCOME & HANDOVER BRIEFING

Respected Sir,

This document is your direct, step-by-step evaluation guide for the complete, working **BI Antivirus Enterprise** platform. 

Every component, test suite, and launcher has been verified to run out-of-the-box on any standard Windows 10 or 11 64-bit computer. All project operations are strictly confined to the `D:\` drive partition (or secondary folder), leaving zero clutter on your Windows `C:\` partition.

---

## 1. EVALUATION MODES: PORTABLE RUNTIME vs. COMMERCIAL BINARY

To ensure absolute transparency during your review:

| Evaluation Dimension | Sovereign User-Space Platform (Current Release) | Commercial GravityZone Binary (Future Enterprise) |
| :--- | :--- | :--- |
| **Execution Format** | Verified Python Source & Portable Distribution Bundle (`.zip`) | Compiled `.msi` Windows Service Installer |
| **Real-Time Monitoring** | High-performance Windows `ReadDirectoryChangesW` (user-space post-write interception in ~50ms) | Kernel Minifilter Driver (`BIAntiVirusFilter.sys`) with synchronous pre-execution thread blocking (`FLT_PRE_OPERATION`) |
| **Process Defense** | Win32 Process Mitigation Policy Auditing (DEP, ASLR, CFG, Dynamic Code) + Post-spawn Win32 `TerminateProcess` | Inline API detours in external processes + Kernel process creation filter (`PsSetCreateProcessNotifyRoutineEx`) |
| **Threat Intelligence** | Local SQLite signature catalog + verifiable local CVE catalog + HMAC-signed `.biu` offline update bundles | Multi-billion hash cloud query engine with global multi-tenant server infrastructure |
| **Code Signing** | Unsigned / Local DPAPI Machine Key Encryption | Extended Validation (EV) HSM Code Signing Certificate + Microsoft WHQL attestation + Microsoft MVI PPL |

---

## 2. SIR'S COMPLETE 10-STEP EVALUATION WORKFLOW

Respected Sir, please follow these tested steps to evaluate the platform on your computer:

### Step 1: Install Python Runtime
Ensure Python **3.10, 3.11, or 3.12 (64-bit)** is installed from [python.org](https://www.python.org). Ensure *"Add python.exe to PATH"* is checked during installation.

### Step 2: Clone or Extract the Repository
```powershell
# Option A: Clone from GitHub
git clone https://github.com/jitendersainik2006-ops/BI-Antivirus.git
cd BI-Antivirus

# Option B: Extract from the Standalone Distribution Archive
# Extract dist/BI_Antivirus_Enterprise_v1.0.0_Portable.zip into D:\bit defender
```

### Step 3: Install Lightweight Dependencies
Open Command Prompt or PowerShell in the project directory:
```powershell
pip install -r requirements.txt
```
*(Only requires `psutil>=5.9.0`; all other engines use standard library `tkinter`, `sqlite3`, `ctypes`, `hashlib`, `hmac`).*

### Step 4: Run the Automated Setup Wizard
```cmd
setup_windows.bat
```
- Validates 64-bit Python and Windows OS build.
- Establishes storage directories on `D:\` (`data/`, `logs/`, `quarantine/vault/`, `reports/`).
- Initializes SQLite databases in WAL mode and pre-seeds test signatures.
- Emits installation report to `data\installation_diagnostic_report.json`.

### Step 5: Execute the Full Automated Test Suite (276 Tests)
```cmd
run_tests.bat
# Or alternatively: python run_tests.py
```
- Runs all **276 automated test cases** across **44 test suites**.
- Expected result: **100% PASS RATE (0 Failures, 0 Errors, 0 Skipped)** in ~150 seconds.

### Step 6: Execute the Clean Environment Acceptance Test
```powershell
python scripts\verify_clean_acceptance.py
```
- Creates an isolated clean-slate directory under `data\clean_acceptance_test`.
- Validates 7 acceptance gates (Tree creation, SQLite WAL, Synthetic threat scan, AES-256 quarantine vault & restoration, XDR Incident Graph, Vulnerability posture score, and clean teardown).
- Expected result: **CLEAN ENVIRONMENT ACCEPTANCE TEST: ALL PASSED (7/7)**.

### Step 7: Run the Harmless 10-Stage Live Demonstration
```cmd
run_demo.bat
# Or alternatively: python scripts\demo_full_lifecycle.py
```
- Demonstrates the complete threat lifecycle in ~5 seconds using harmless synthetic indicators:
  1. Environment setup & WAL database init.
  2. Multi-threaded signature scanning (EICAR / test virus).
  3. Shannon entropy heuristic ransomware detection.
  4. Anti-ransomware Canary decoy tripwire detection (<100ms).
  5. Cryptographic AES-256 quarantine vault isolation.
  6. Safe, 100% reversible file restoration with SHA-256 integrity audit.
  7. EDR Incident Graph correlation and MITRE ATT&CK mapping.
  8. Non-blocking automated hot database backup generation.

### Step 8: Launch the Desktop GUI Dashboard (13 Views)
```cmd
run_gui.bat
# Or alternatively: python main.py
```
Explore the 13 interactive operational views:
- **Dashboard:** System health score, live telemetry, diagnostic posture.
- **Scan Center:** Quick Scan, Full Scan, and Custom directory scanning.
- **Quarantine Vault:** AES-256 encrypted vault inspection, restore, and purge.
- **Threat History:** Immutable SQLite audit trail with search filters.
- **Real-Time & Web:** Sentinel status, Canary token controls, MOTW ingress tracking.
- **Firewall & Network:** Inbound/outbound rule manager, dangerous port auditor, emergency rollback.
- **Automation & Voice:** Loopback API status and threat alert triggers.
- **Settings & Exclusions:** Heuristics toggles, scan exclusions, and update thresholds.
- **Security Reports:** Compliance report generator (ISO 27001, SOC 2, HIPAA).
- **EDR & Exploit Shield:** Process memory mitigation table (DEP/ASLR/CFG/RWX) and incident trees.
- **Software & Patching:** Windows Registry software inventory and local CVE advisory correlation.
- **PE Classifier:** Static PE header analyzer with Shannon section entropy.
- **Fleet Management:** Agent enrollment, heartbeats, and signed policy distribution.

### Step 9: Review Handover Documentation
Inspect the exhaustive documentation package in `submission/`:
- `FINAL_PARITY_GAP_AUDIT.md`: Complete baseline audit and 30-capability matrix.
- `FINAL_IMPLEMENTATION_REPORT.md`: Comprehensive engineering report.
- `FINAL_TEST_REPORT.md`: Granular breakdown of all 276 tests and 44 suites.
- `FINAL_SECURITY_REPORT.md`: Detailed cryptographic and security audit.
- `FINAL_FEATURE_PARITY_MATRIX.md`: Category-by-category Bitdefender comparison.
- `KNOWN_LIMITATIONS.md`: Honest technical disclosure of user-space boundaries.

### Step 10: Safe Uninstallation
```cmd
uninstall_windows.bat
```
- Standard Mode: Uninstalls runtime scripts while safely preserving user databases, quarantine vaults, and reports on `D:\`.
- Complete Purge Mode: Fully purges all local data upon explicit confirmation.

---

## 3. CONTACT & TECHNICAL SUPPORT

Respected Sir, should you encounter any environment-specific questions during your evaluation:
- Review [docs/TROUBLESHOOTING.md](file:///D:/bit%20defender/docs/TROUBLESHOOTING.md) for 10 common environment resolutions.
- System diagnostics can be regenerated at any time via: `python main.py status`.

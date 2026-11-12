# BI ANTIVIRUS ENTERPRISE — FINAL INSTALLATION & DEPLOYMENT GUIDE
**Project Root:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Target Platform:** Windows 10, Windows 11, Windows Server 2019/2022/2025 (x64)  
**Version:** 2.0 Enterprise Production Release  
**Automated Test Suite:** **273/273 Passed (100% Success across 44 test suites)**

---

## 1. System Requirements & Compatibility Baseline

### Hardware Requirements
- **CPU:** Dual-core 2.0 GHz or higher (x64 architecture).
- **RAM:** 4 GB minimum (8 GB recommended for enterprise fleet and incident correlation).
- **Storage:** Minimum 500 MB free space on `D:` drive for binaries, SQLite WAL databases, incident graph cache, and AES-256 encrypted quarantine vault.

### Software Prerequisites
- **Operating System:** Microsoft Windows 10/11 (Build 19041+ or Win 11 Build 22000+) 64-bit. Verified on Windows 11 Build 26300.
- **Python Runtime:** Python 3.10 through 3.12 64-bit (`python.exe` must be 64-bit to audit 64-bit Win32 processes without WOW64 truncation).
- **Windows Subsystem Features:**
  - Win32 CryptoAPI / DPAPI (Native Windows Data Protection API).
  - Windows Management Instrumentation (WMI / CIM) for disk encryption and hardware audits.
  - Windows Defender coexistence (Native cooperation without driver conflicts).

### Privilege Modes & Capabilities
BI Antivirus operates in two distinct privilege modes with dynamic capability reporting:
1. **Administrator Mode (Full Enforcement):**
   - Active host firewall rule manipulation via `netsh advfirewall`.
   - Windows Defender exclusion configuration and coexistence management.
   - Low-level process token inspection (`SeDebugPrivilege`) and termination.
   - Physical USB hardware write-protect registry policy enforcement.
2. **Standard User Mode (Audit & User-Space Protection):**
   - User-space file scanning, static heuristic PE parsing, machine learning scoring.
   - Encrypted Quarantine Vault isolation and safe restoration.
   - Real-time directory monitoring on user-accessible directories.
   - EDR causal incident graph generation, RCA analysis, and SIEM logging.
   - Firewall and privilege status displayed with clear "Audit-Only / Visibility" indicators.

---

## 2. Strict D: Drive Confinement Rules

To ensure enterprise data sovereignty and prevent accidental system partition pollution, BI Antivirus enforces strict storage containment on `D:`:
- **Base Root:** `D:\bit defender`
- **NTFS Junction:** `D:\BI-Antivirus` (points to `D:\bit defender`)
- **Database Directory:** `D:\bit defender\data\` (`signatures.db`, `history.db`, `quarantine.db`, `fleet.db`)
- **Lock & Recovery File:** `D:\bit defender\data\bi_antivirus.lock` (PID + heartbeat)
- **Quarantine Vault:** `D:\bit defender\quarantine\vault\` (AES-256 encrypted payloads + HMAC tags)
- **Application Logs:** `D:\bit defender\logs\` (`app.log`, `audit.log` with automatic 10MB rotation)
- **Benchmark & Diagnostic Data:** `D:\bit defender\data\installation_diagnostic_report.json`

---

## 3. Automated First-Run Setup Wizard (`scripts/install_windows.py`)

BI Antivirus provides an automated, non-destructive Windows deployment wizard that validates the environment, sets up directories, verifies SQLite WAL mode, and generates an installation diagnostic report.

### Step 1: Clone or Navigate to Project Directory
```powershell
# Open PowerShell (Administrator recommended for full enforcement)
cd D:\
if (!(Test-Path "D:\bit defender")) {
    git clone https://github.com/jitendersainik2006-ops/BI-Antivirus.git "bit defender"
}
cd "D:\bit defender"
```

### Step 2: Install Python Dependencies
```powershell
python -m pip install -r requirements.txt
```
*Core packages installed:*
- `cryptography` (AES-256, HMAC-SHA256, PBKDF2, X.509 PKI certificates)
- `psutil` (Process enumeration and memory auditing)
- `pefile` (PE structural inspection and entropy analysis)

### Step 3: Execute Automated Installation Wizard
```powershell
python scripts/install_windows.py
```
*Wizard Execution Sequence:*
1. **Pre-flight Compatibility Audit:** Checks Python version (3.12 64-bit), OS build, privilege level, D: drive compliance, and crypto availability.
2. **Directory Tree Provisioning:** Initializes `data/`, `logs/`, `quarantine/vault/`, and `backups/`.
3. **Database Initialization & WAL Optimization:** Verifies SQLite `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`, and secondary index structures.
4. **Configuration Generation:** Generates default `data/settings.json` and `data/detection_rules.json`.
5. **Crash Recovery Initialization:** Configures `CrashRecoveryManager` and prepares single-instance lock handling.
6. **Diagnostics Report Export:** Writes machine-readable JSON report to `data/installation_diagnostic_report.json`.

---

## 4. Verification & Automated Test Suite Execution

Before running production services, execute the comprehensive automated test suite:
```powershell
python run_tests.py
```
*Expected Output:*
```text
======================================================================
      BI ANTIVIRUS - AUTOMATED VALIDATION TEST SUITE
======================================================================
Ran 255 tests in ~90s
OK
======================================================================
Tests Run:      255
Failures:       0
Errors:         0
Skipped:        0
Overall Status: SUCCESS (ALL TESTS PASSED)
======================================================================
```

---

## 5. Launching BI Antivirus

### Option A: Interactive Desktop Management Console (Primary GUI)
To launch the full 13-view enterprise desktop interface:
```powershell
python main.py
```
*Features available in the GUI:*
- **Overview View:** Real-time protection status card, Quick/Full/Custom scan triggers, System Diagnostics modal, and Administrator privilege breakdown.
- **Scanner View:** Real-time file scanning with progress indicators, threat lists, and exclusion options.
- **Quarantine View:** AES-256 encrypted vault management, one-click "Verify Vault Integrity", safe restoration, and permanent purge.
- **EDR & Incident Graph View:** Interactive root-cause analysis (RCA) causal graph, MITRE ATT&CK technique tags, and forensic timeline.
- **Fleet View:** Multi-tenant endpoint management notebook, mTLS agent enrollment, and policy distribution.
- **Settings View:** Detection engine tuning, SQLite database integrity check (`PRAGMA integrity_check`), online hot database backup, and SIEM CEF/RFC 5424 export test.

### Option B: Headless Command-Line Interface (CLI & Status)
Check the runtime health, process ID, and crash recovery lock without launching GUI:
```powershell
python main.py status
```
*Output:*
```text
==================================================
  BI ANTIVIRUS ENTERPRISE - STATUS
==================================================
  Process Status:   STOPPED (No active process)
  PID Lock File:    IDLE
  Project Root:     D:\bit defender
  Quarantine Vault: D:\bit defender\quarantine\vault
  Integrity Status: READY
==================================================
```

---

## 6. Windows Defender Coexistence Configuration

BI Antivirus is designed to operate safely alongside Windows Defender without kernel collision:
1. **Non-Colliding Engine:** BI Antivirus operates strictly in user-space using Win32 notification sentinels (`ReadDirectoryChangesW`) rather than an uncertified kernel minifilter.
2. **Exclusion Setup (Optional):** When running in elevated mode, add BI Antivirus data directories to Defender exclusions to prevent Defender from inspecting the encrypted quarantine vault:
```powershell
Add-MpPreference -ExclusionPath "D:\bit defender\quarantine\vault"
Add-MpPreference -ExclusionPath "D:\bit defender\data"
```
3. **Firewall Harmony:** BI Antivirus manages specific application rules via `netsh advfirewall` without overriding or disabling the primary Windows Defender Firewall service.

---

## 7. Troubleshooting & Recovery

| Issue | Cause | Resolution |
|---|---|---|
| `Lock file active (PID XXXX)` | Previous instance was abruptly terminated | Run `python main.py status`. `CrashRecoveryManager` automatically detects dead PIDs and removes stale locks. |
| `PermissionError on Firewall` | Running in Standard User mode | Normal behavior. BI Antivirus automatically activates "Audit-Only / Visibility Mode" for firewall controls. Run as Administrator for full enforcement. |
| `SQLite database locked` | High concurrent access | SQLite WAL mode and `busy_timeout=5000` handle concurrent queries. Use "Verify DB Integrity" in Settings view if corruption is suspected. |
| `Missing dependency` | Python environment mismatch | Ensure Python 3.12 64-bit is active and execute `pip install -r requirements.txt`. |

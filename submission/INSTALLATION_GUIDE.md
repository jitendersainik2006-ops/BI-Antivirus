# BI ANTIVIRUS ENTERPRISE — INSTALLATION & DEPLOYMENT MANUAL
**Platform:** Windows 10, Windows 11, Windows Server 2019/2022/2025 (x64)  
**Target Storage Path:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Python Runtime:** Python 3.10, 3.11, or 3.12 (64-bit required)  
**Release Version:** 2.0 Enterprise Production Release  

---

## 1. System Requirements

### Hardware Requirements
* **Processor:** 64-bit Dual-Core 2.0 GHz or higher (x64 architecture).
* **System Memory:** 4 GB RAM minimum (8 GB recommended for enterprise fleet and incident correlation).
* **Storage Space:** Minimum 500 MB free space on volume `D:` for binaries, SQLite WAL databases, incident graph cache, and AES-256 encrypted quarantine vault.

### Software Prerequisites
* **Operating System:** Microsoft Windows 10 (Version 2004+), Windows 11, or Windows Server 2019/2022/2025 (64-bit).
* **Python Runtime:** Python 3.12 64-bit installed. (Must be 64-bit to audit 64-bit Win32 processes without WOW64 memory truncation).
* **Windows Facilities:**
  * Windows Data Protection API (DPAPI) and CryptoAPI (`advapi32.dll`, `crypt32.dll`).
  * Windows Management Instrumentation (WMI / CIM) for disk encryption and hardware audits.
  * Windows Defender coexistence (native cooperation without uncertified driver conflicts).

---

## 2. Fast Deployment & Setup Instructions

### Step 1: Clone or Open the Repository
```powershell
# Ensure working directory is on D:
cd "D:\bit defender"
```

### Step 2: Set Up Python Dependencies
```powershell
# Install core Python requirements (sandboxed or virtual environment)
pip install -r requirements.txt
```

### Step 3: Run the Environment & Compatibility Setup Script
```powershell
# Run the automated Windows setup wizard (or double-click setup_windows.bat)
.\setup_windows.bat
# Or alternatively: python scripts/install_windows.py
```

### Step 4: Verify the Installation & Run Tests
```powershell
# Check engine status
python main.py status

# Run automated validation suite (all 273 tests)
.\run_tests.bat
# Or alternatively: python run_tests.py
```

### Step 5: Launch GUI or Live Demonstration
```powershell
# Launch Desktop GUI Console (13 Views)
.\run_gui.bat
# Or alternatively: python main.py --gui

# Run Harmless Live Demonstration (10 Stages)
.\run_demo.bat
# Or alternatively: python scripts/demo_full_lifecycle.py
```

---

## 3. Directory Structure & Confinement Architecture

All application files and data are strictly confined to `D:\bit defender`:

```
D:\bit defender\
├── bi_antivirus/           # Core Python source packages
│   ├── api/                # REST API and webhook daemons
│   ├── core/               # Detector, scanner, quarantine, EDR graph
│   ├── database/           # SQLite schema and history models
│   ├── enterprise/         # PKI, mTLS, fleet manager, RBAC, SIEM
│   ├── monitors/           # Real-time, exploit, firewall, ransomware
│   ├── tests/              # 44 automated unit & integration test suites
│   └── ui/                 # Desktop GUI console and 13 views
├── config/                 # Platform configuration files
├── data/                   # SQLite databases (history.db, fleet.db)
│   └── backups/            # Non-blocking online hot database snapshots
├── docs/                   # Exhaustive technical and architectural documentation
├── logs/                   # Local diagnostic and audit logs
├── quarantine/
│   └── vault/              # AES-256-CBC encrypted vaulted files (.biq)
├── reports/                # EDR Root Cause Analysis (RCA) and compliance markdown reports
├── scripts/                # Installation, benchmarking, and demonstration scripts
├── submission/             # Official submission deliverables for Sir
├── main.py                 # Primary application entry point (GUI / CLI)
└── run_tests.py            # Master automated test suite runner
```

---

## 4. Privilege Modes & Operating States

BI Antivirus Enterprise dynamically adapts to the current Windows user token:

1. **Administrator Mode (Full Enforcement):**
   * Active host firewall manipulation via `netsh advfirewall`.
   * Low-level process token inspection (`SeDebugPrivilege`) and termination.
   * Physical USB hardware write-protect registry enforcement.
   * Windows Defender exclusion configuration.
2. **Standard User Mode (Audit & User-Space Protection):**
   * High-speed heuristic file scanning and machine learning scoring.
   * Encrypted Quarantine Vault isolation and safe restoration.
   * Real-time file change monitoring on user-accessible directories.
   * EDR causal incident graph generation, RCA analysis, and SIEM logging.
   * Status indicators clearly display "Visibility Mode / Audit-Only" when unprivileged.

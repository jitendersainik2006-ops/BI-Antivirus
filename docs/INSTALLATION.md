# BI Antivirus — Installation & Deployment Guide

## 1. System Requirements

| Parameter | Minimum Requirement | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Windows 10 (64-bit, Build 19041+) | Windows 11 (64-bit, Version 22H2+) |
| **Processor** | Dual-Core x86-64 CPU (2.0 GHz) | Quad-Core x86-64 CPU (2.5+ GHz) |
| **RAM** | 2 GB Available RAM | 4 GB Available RAM (App footprint: < 35 MB) |
| **Disk Storage** | 2 GB free space on secondary drive `D:` | 10 GB free space on secondary drive `D:` |
| **Runtime Dependencies** | Python 3.12 (64-bit) | Python 3.12 (64-bit), Node.js v20+ (for n8n) |
| **Network Requirements** | Offline capable; Loopback `127.0.0.1` | Loopback only (Zero internet access required) |

---

## 2. Directory Containment on D: Drive

The canonical workspace root is strictly located at:
```
D:\bit defender\   (or NTFS Junction D:\BI-Antivirus)
```

All operational data, databases, and logs are segregated into dedicated folders:
```
D:\bit defender\
├── bi_antivirus\         # Core Python application package
│   ├── api\              # Local REST API and n8n bridge daemon
│   ├── core\             # Scanning, detection, authenticode, quarantine
│   ├── database\         # SQLite history and signature managers
│   ├── monitors\         # Behavioral, ransomware, USB, realtime sentinels
│   ├── network\          # Firewall and web reputation shield
│   ├── tests\            # Automated regression test suite (67 tests)
│   └── ui\               # Tkinter dark cyber GUI dashboard
├── config\               # Configurations and n8n environment templates
│   └── n8n\n8n.env.example
├── data\                 # Local databases (quarantine.db, history.db, signatures.db)
├── logs\                 # Security audit and event logs (bi_security.log)
├── n8n\                  # Genuine n8n Community Edition runtime files
├── quarantine\vault\     # Authenticated AES-256 quarantine vault (.biq)
├── reports\              # Generated security assessment markdown reports
├── scripts\              # Management scripts and resilience benchmarks
├── run_gui.bat           # One-click desktop GUI launcher
├── run_cli.bat           # Command-line interface launcher
├── run_tests.bat         # Automated regression test runner
└── run_n8n.bat           # Local n8n automation bridge daemon launcher
```

---

## 3. Step-by-Step Setup Instructions

### Step 1: Clone or Copy Project to Drive D:
Ensure the repository resides directly on `D:\bit defender`:
```cmd
cd /d D:\
git clone https://github.com/jitendersainik2006-ops/BI-Antivirus.git "bit defender"
```

### Step 2: Configure Environment Files
Copy the sanitized n8n environment template to create your local config:
```cmd
cd /d "D:\bit defender"
copy config\n8n\n8n.env.example config\n8n\n8n.env
```
Ensure `config\n8n\n8n.env` has `N8N_RUNNERS_BROKER_PORT=5680` configured to avoid port collisions with the web UI on `5679`.

### Step 3: Run the Automated Validation Suite
Execute the full test suite to verify all 67 tests pass:
```cmd
run_tests.bat
```
Expected output:
```
Tests Run:      67
Failures:       0
Errors:         0
Overall Status: SUCCESS (ALL TESTS PASSED)
```

### Step 4: Launch Desktop GUI Dashboard
```cmd
run_gui.bat
```
The dark cyber dashboard will render on the desktop, displaying real-time protection metrics, sentinel indicators, and scan options.

### Step 5: Start Local Automation Services (Optional)
If running automated workflow diagnostics:
1. Start the BI Antivirus REST API:
   ```cmd
   python scripts\start_api_server.py
   ```
2. Start the n8n Bridge Daemon:
   ```cmd
   run_n8n.bat
   ```
Both services bind exclusively to `127.0.0.1` and communicate over loopback.

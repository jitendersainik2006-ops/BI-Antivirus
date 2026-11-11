# BI ANTIVIRUS ENTERPRISE — INSTALLATION & DEPLOYMENT GUIDE
**Project Root:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Target Platform:** Windows 10, Windows 11, Windows Server 2019/2022 (x64)  
**Version:** 2.0 Enterprise  

---

## 1. System Requirements

### Hardware Requirements
- **CPU:** Dual-core 2.0 GHz or higher (x64 architecture).
- **RAM:** 4 GB minimum (8 GB recommended for enterprise fleet console).
- **Storage:** 500 MB free space on `D:` drive for binaries, models, logs, and quarantine vault.

### Software Prerequisites
- **Operating System:** Microsoft Windows 10/11 x64 or Windows Server 2019/2022.
- **Python Runtime:** Python 3.10 through 3.12 (Tested on Python 3.12.8 x64).
- **Permissions:** Standard User for desktop scanning; Elevated Administrator required for Windows Firewall management, BitLocker WMI inspection, and low-level process privilege auditing.

---

## 2. Directory Architecture & Confinement Rules

To ensure enterprise data sovereignty and avoid cluttering system partitions, BI Antivirus enforces strict storage containment on `D:`:
- **Base Root:** `D:\bit defender`
- **NTFS Junction:** `D:\BI-Antivirus` (points to `D:\bit defender`)
- **Database Directory:** `D:\bit defender\data\` (`signatures.db`, `quarantine.db`, `fleet.db`)
- **Quarantine Vault:** `D:\bit defender\quarantine\vault\` (AES-256 encrypted records)
- **Application Logs:** `D:\bit defender\logs\` (`app.log`, `audit.log`)

---

## 3. Step-by-Step Installation

### Step 1: Clone or Verify Repository
```powershell
# Open PowerShell as Administrator
cd D:\
if (!(Test-Path "D:\bit defender")) {
    git clone https://github.com/jitendersainik2006-ops/BI-Antivirus.git "bit defender"
}
cd "D:\bit defender"
```

### Step 2: Install Python Dependencies
```powershell
# Install required dependencies into current Python environment
python -m pip install -r requirements.txt
```
*Core dependencies include:*
- `PyQt6` (Desktop GUI)
- `cryptography` (AES-256-CBC, PBKDF2, X.509 PKI, HMAC-SHA256)
- `psutil` (Process inspection & memory auditing)
- `pefile` (Static PE structural header analysis)

### Step 3: Verify Integrity & Execute Test Suite
Before launching production services, verify that all 230 automated validation tests pass:
```powershell
python run_tests.py
```
*Expected output:*
```text
Ran 230 tests in ~160s
OK
======================================================================
Tests Run:      230
Failures:       0
Errors:         0
Skipped:        0
Overall Status: SUCCESS (ALL TESTS PASSED)
======================================================================
```

---

## 4. Launching BI Antivirus

### Option A: Interactive Desktop GUI Console
To launch the dark-mode Bitdefender-inspired desktop graphical interface:
```powershell
python main.py
```
The GUI provides real-time status cards, quick/full scan controls, interactive quarantine management, threat intelligence indicators, and live settings management.

### Option B: Headless Background Sentinel Service
To run as a lightweight background security monitoring service:
```powershell
python -m bi_antivirus.service
```

### Option C: Enterprise Fleet API Server
To start the centralized fleet management server with TLS and REST API:
```powershell
python -c "from bi_antivirus.enterprise.fleet_manager import FleetManager; fm = FleetManager(); fm.start_api_server(port=8765)"
```

---

## 5. Enterprise Fleet Enrollment & Policy Sync

1. **Generate Root CA & Server Certificates:**
   ```powershell
   python -c "from bi_antivirus.enterprise.pki_manager import PKIManager; pki = PKIManager(); pki.initialize_pki()"
   ```
2. **Issue Endpoint Enrollment Token:**
   ```powershell
   python -c "from bi_antivirus.enterprise.enrollment_manager import EnrollmentManager; em = EnrollmentManager(); print('Token:', em.create_enrollment_token('CORP-WS-01', 'Workstation'))"
   ```
3. **Enroll Local Machine:**
   Use the generated one-time token in the GUI or via script to establish cryptographic mutual TLS binding.

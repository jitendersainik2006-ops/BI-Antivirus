# BI ANTIVIRUS ENTERPRISE — FINAL DEMONSTRATION GUIDE
**Audience:** Project Supervisor, Evaluation Committee, and Senior Directorate  
**Project Root:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Platform:** Windows 10, Windows 11, Windows Server 2019+ (x64)  
**Execution Safety:** 100% Harmless Synthetic Test Fixtures (Zero Live Malware, Zero Disruptive Firewall Cuts)  
**Estimated Time:** ~5–7 Minutes  

---

## 1. Quick Master Demonstration (Recommended)

To evaluate the complete end-to-end lifecycle in a single automated command (~5 seconds):

```powershell
# Method A: Double-click run_demo.bat in Windows Explorer, or run:
.\run_demo.bat

# Method B: Run directly via Python:
python scripts/demo_full_lifecycle.py
```

### What This Master Script Automatically Validates:
1. **Engine Architecture & Storage Confinement Audit:** Initializes the engine and verifies 100% confinement to `D:\bit defender`.
2. **Multi-Vector Synthetic Scan:** Creates disposable test files and audits benign documents alongside synthetic threat signatures.
3. **Cryptographic Quarantine Vault Isolation:** Quarantines a detected threat into the encrypted AES-256-CBC + HMAC-SHA256 vault (`quarantine/vault/`).
4. **Physical Vault Integrity Verification:** Executes cryptographic integrity verification across all vaulted `.biq` files.
5. **Persistent Threat History Audit:** Queries SQLite WAL database to verify transaction recording.
6. **Reversible Safe File Restoration:** Restores the quarantined file, validates byte-for-byte SHA-256 checksum matching, and securely purges the disposable sample.
7. **EDR Causal Incident Graph Synthesis:** Ingests process execution and alert telemetry, correlating parent-child nodes into a MITRE ATT&CK mapped incident.
8. **Forensic Root Cause Analysis (RCA) Export:** Generates an executive markdown incident report in `reports/`.
9. **Database Concurrency & Online Hot Backup:** Checks SQLite WAL journal mode and executes an online hot database snapshot to `data/backups/`.
10. **Zero-Trust Enterprise Fleet Telemetry:** Registers an endpoint device and generates CIS compliance posture metrics.

---

## 2. Interactive Graphical Desktop Console Demonstration

To demonstrate the full desktop graphical interface:

```powershell
# Method A: Double-click run_gui.bat in Windows Explorer, or run:
.\run_gui.bat

# Method B: Run directly via Python:
python main.py --gui
```

### Guided Walkthrough of Key Views:

1. **Overview View (Dashboard):**
   * Review endpoint status (`PROTECTED`).
   * Click **System Diagnostics** to view the live readiness dialog.
   * Click **Privilege Details** to observe dynamic elevation reporting.
2. **Scanner View:**
   * Select **Quick Scan** or **Custom Scan** (target `D:\bit defender\demo_live`).
   * Observe real-time progress indicators and detection feeds.
3. **Quarantine View:**
   * View encrypted vaulted threats.
   * Click **Verify Vault Integrity** to trigger physical cryptographic HMAC validation.
   * Select an item and review file metadata and safe restore options.
4. **EDR Incidents View:**
   * Review synthesized incident graphs and correlated MITRE ATT&CK techniques.
   * Click **Export RCA** to inspect formatted forensic markdown investigation reports.
5. **Settings View:**
   * Under Database Maintenance, click **Check DB Integrity** to execute SQLite `PRAGMA integrity_check`.
   * Click **Create Backup Now** to verify online non-blocking hot database snapshots.

---

## 3. Command Line Interface (CLI) Demonstration

For headless or automated server administration:

### Check System Status:
```powershell
python main.py status
```
*Outputs current engine status, signature counts, definitions version, and database paths.*

### Run an On-Demand Custom Directory Scan:
```powershell
python main.py scan --custom "D:\bit defender\demo_live"
```

### Execute the Full Automated Test Suite:
```powershell
python run_tests.py
```
*Executes all 273 unit and integration tests across 44 test suites in ~75 seconds.*

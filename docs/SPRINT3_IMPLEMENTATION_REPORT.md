# BI Antivirus — Sprint 3 Technical Implementation Report
**Document Version:** 1.0.0  
**Project:** BI Antivirus — Threat Protection Platform  
**Target Environment:** Windows 10/11 Enterprise / Server (Canonical Storage: `D:\bit defender`, Junction: `D:\BI-Antivirus`)  
**Publication Repository:** `https://github.com/jitendersainik2006-ops/BI-Antivirus`  
**Test Suite Status:** **117 / 117 Passing (100% Automated Coverage)**  
**Baseline Commit:** `07ca63697544413dfa8eb15d1cfb18b00837776d`

---

## Executive Summary

Sprint 3 represents a major milestone in advancing BI Antivirus toward full functional feature parity with Bitdefender GravityZone Business Security Enterprise. This sprint delivers four high-impact defensive enterprise modules, a storage migration and containment audit ensuring 100% residency on the `D:` drive, an upgraded evidence classification architecture for EDR telemetry, and dedicated enterprise desktop dashboard views.

All implementations strictly adhere to Bitdefender-inspired functional architecture without infringing on proprietary source code, trademarks, or copyrighted assets. Every capability is verified via live Windows operating system integration and automated regression testing.

---

## 1. Storage Containment & C: to D: Migration Audit

As mandated by Phase 1 of the Sprint 3 master prompt, an exhaustive filesystem audit was conducted across the host workstation:
- **Project Storage:** Canonical workspace `D:\bit defender` (Junction `D:\BI-Antivirus`).
- **Scratch and Sandbox Directory:** `D:\bit defender\data\crypto_test_scratch\` canonically established in `bi_antivirus/config.py` as `SCRATCH_DIR`.
- **System Isolation:** Confirmed zero project databases (`.db`), quarantine vaults (`.biq`), logs, or test artifacts on `C:`. Global Python 3.12 (`C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312`) is strictly treated as a shared read-only system interpreter.
- **Test Hardening:** Refactored `test_ransomware_shield.py` and `test_usb_sentinel.py` to eliminate unconstrained `tempfile.mkdtemp()` calls in favor of `D:\bit defender\data\crypto_test_scratch\`.
- **Audit Documentation:** Documented comprehensively in [`docs/C_DRIVE_MIGRATION_AUDIT.md`](file:///D:/bit%20defender/docs/C_DRIVE_MIGRATION_AUDIT.md).

---

## 2. Core Architectural Deliverables

### Component A: Local PE Security Classifier (`bi_antivirus/core/pe_classifier.py`)
A static binary feature extraction and heuristic classification engine built natively using Python's standard `struct` library without external binary dependencies:
- **PE32 / PE32+ Header Parsing:** Unpacks DOS header (`e_lfanew`), COFF header (Machine type, NumberOfSections, TimeDateStamp, SizeOfOptionalHeader, Characteristics), and OptionalHeader (AddressOfEntryPoint, ImageBase, SectionAlignment, Subsystem, DllCharacteristics).
- **Section Table Inspection:** Iterates all PE section headers; extracts VirtualAddress, VirtualSize, SizeOfRawData, PointerToRawData, and section characteristics.
- **Dangerous Section Permissions:** Evaluates `IMAGE_SCN_MEM_EXECUTE` combined with `IMAGE_SCN_MEM_WRITE` (0xE0000000) to detect RWX memory sections commonly used for self-decrypting shellcode, packers, and process injection trampolines (+35 risk points).
- **Shannon Entropy Calculation:** Computes Shannon entropy ($H = -\sum p_i \log_2 p_i$) per section. Sections exhibiting $H \ge 7.0$ are flagged as compressed or encrypted payloads.
- **Import Address Table (IAT) Parsing:** Resolves Import Directory table and extracts imported DLLs and API symbols, categorizing high-risk APIs:
  - *Process Injection:* `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `NtMapViewOfSection`.
  - *Process Creation:* `CreateProcessW`, `WinExec`, `ShellExecuteW`.
  - *Evasion / Anti-Analysis:* `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`.
  - *Network C2:* `InternetOpenUrlW`, `URLDownloadToFileW`, `HttpSendRequestW`, `connect`.
  - *Ransomware Primitives:* `CryptEncrypt`, `BCryptEncrypt`, `CryptGenKey`.
- **Compiler Mitigations Auditing:** Inspects `DllCharacteristics` for Data Execution Prevention (DEP / NX), Address Space Layout Randomization (ASLR / DynamicBase), High Entropy 64-bit ASLR, and Control Flow Guard (CFG).
- **Overlay Detection:** Identifies and measures unmapped data appended beyond the last raw section boundary, computing its Shannon entropy.
- **Explainable Scoring Heuristics:** Assigns a deterministic suspicion score (0 to 100) paired with explicit human-readable reasons, classifying binaries into `BENIGN_PROBABLE`, `BENIGN_VERIFIED`, `SUSPICIOUS`, or `MALICIOUS_SUSPECT`.

### Component B: Software Inventory & Patch Auditor (`bi_antivirus/monitors/patch_auditor.py`)
An enterprise vulnerability and patch management sentinel targeting third-party application security:
- **Registry Discovery:** Read-only querying of Windows Uninstall registry hives:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit)
  - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit WOW64)
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (User-installed applications)
- **Verifiable Local CVE Advisory Catalog:** Built-in catalog for high-target Windows applications:
  - *7-Zip:* CVE-2023-31102, CVE-2023-40481 (Fixed in 23.01)
  - *WinRAR:* CVE-2023-38831, CVE-2023-40477 (Fixed in 6.23)
  - *Google Chrome:* CVE-2024-4671, CVE-2024-5274 (Fixed in 125.0.6422.141)
  - *Git for Windows:* CVE-2024-32002, CVE-2024-32004 (Fixed in 2.45.1)
  - *Notepad++:* CVE-2023-40031 (Fixed in 8.5.7)
  - *Zoom Workplace:* CVE-2024-45421 (Fixed in 6.2.0)
  - *VLC Media Player:* CVE-2023-47359 (Fixed in 3.0.20)
  - *Python:* CVE-2024-0450 (Fixed in 3.12.3)
- **Semantic Version Parsing & Comparison:** Normalizes version strings into integer tuples via `parse_version_tuple()` and performs strict mathematical boundary comparisons (`is_version_vulnerable()`).
- **Classification Statuses:** Applications are tagged as `CONFIRMED_VULNERABLE`, `UP_TO_DATE`, or `UNKNOWN`.
- **Zero-Silent-Modifications Policy:** Strictly avoids automated or unapproved background installations. Every detected vulnerability produces an actionable manual remediation playbook and requires explicit administrator consent.

### Component C: Threat Intelligence Update Engine (`bi_antivirus/core/threat_intel.py`)
A secure, offline-capable threat intelligence feed ingestion subsystem:
- **HMAC-SHA256 Cryptographic Signing:** Signs and validates update bundles using Windows DPAPI machine keys (`PolicyKeyManager.get_signing_key()`).
- **Anti-Rollback & Monotonic Sequence Protection:** Rejects update bundles with sequence numbers less than or equal to the currently applied sequence, preventing downgrade and replay attacks.
- **Tamper Detection:** Computes SHA-256 payload digests and compares against the cryptographically signed manifest declaration before applying updates.
- **Atomic Database Application:** Applies new threat hashes to `SignatureDatabase` and updates local CVE advisories in `HistoryDatabase` within an atomic transaction.
- **Offline Package Import:** Supports importing signed `.biu` and `.json` update packages without external network access or telemetry leakage.

### Component D: Evidence-Backed MITRE Classification (`bi_antivirus/core/incident_graph.py`)
Enhances the EDR incident graph correlation engine with rigorous evidence categorization:
- **Evidence Classification Enum:**
  - `OBSERVED_FACT`: Objectively logged endpoint telemetry (e.g., standard process spawns, standard outbound web sockets). Explicitly never treated as standalone proof of compromise.
  - `SUSPICIOUS_INDICATOR`: Behavioral anomalies (e.g., obfuscated PowerShell `-enc`, trusted LOLBin proxy execution, RWX memory pages). Requires corroborating telemetry.
  - `CONFIRMED_DETECTION`: Verifiable security violations (e.g., signature match, shadow copy deletion `vssadmin delete shadows`, ransomware encryption burst, application control policy block).
- **Source References:** Telemetry events include concrete source subsystem references (`ThreatDetector.SignatureMatch`, `ExploitShield.VirtualQueryEx`, `RansomwareShield.EntropyBurst`, `Win32.ProcessCreation`).
- **Forensic Markdown Reporting:** Generates SOC-grade investigation reports displaying Technique ID, Name, Tactic, Evidence Classification, Confidence Percentage, Source Reference, and Concrete Observable Evidence.

### Component E: Ransomware Shield Improvements (`bi_antivirus/monitors/ransomware_shield.py`)
Upgraded anti-extortion protection:
- **Entropy Transition Tracking:** Monitors file writes and modifications for transitions from structured low-entropy plaintext ($H < 5.0$) to high-entropy ciphertext ($H \ge 7.2$ with $\Delta H \ge 2.0$), identifying encryption in progress before extensions are renamed.
- **Harmless Simulation Test Harness:** Built-in `simulate_ransomware_scenario(scratch_dir)` executing a controlled, harmless test using dummy files in `D:\bit defender\data\crypto_test_scratch\`, asserting interception, and performing clean file cleanup.
- **Actionable Recovery Guidance:** Provides clear, step-by-step administrative recovery guidance strings across all ransomware alerts.

### Component F: Enterprise GUI Views (`bi_antivirus/ui/views/`)
- **Software Inventory & Patch Auditor View (`patch_view.py`):**
  - Displays total installed applications, up-to-date count, confirmed vulnerable count, and active CVE advisories.
  - Treeview showing application name, installed version, publisher, patch status, and matched CVEs.
  - Remediation playbook panel displaying step-by-step manual update instructions.
  - Markdown report export button for compliance audits.
- **PE Static Security Inspector View (`pe_view.py`):**
  - File browser to inspect any Windows binary (`.exe`, `.dll`, `.sys`).
  - Stat cards for Verdict, Suspicion Score, Architecture, and Section Count.
  - Tabbed interface: Sections & Entropy table (with RWX alerts), Suspicious APIs breakdown, and Compiler Mitigations checklist.
  - Forensic Markdown report export.
- **Dashboard Navigation (`dashboard.py`):**
  - Seamlessly integrated into sidebar navigation with dedicated items: `📦 Software & Patching` and `🔬 PE Static Inspector`.

---

## 3. Database Schema Migrations

The SQLite history database (`D:\bit defender\data\history.db`) was upgraded in `bi_antivirus/database/history.py` to incorporate four dedicated relational tables:

```sql
-- 1. Discovered software inventory
CREATE TABLE IF NOT EXISTS software_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name TEXT NOT NULL,
    version TEXT NOT NULL,
    publisher TEXT,
    install_date TEXT,
    install_location TEXT,
    vulnerability_status TEXT DEFAULT 'UNKNOWN',
    matched_cve TEXT,
    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Local verifiable CVE advisories
CREATE TABLE IF NOT EXISTS cve_advisories (
    cve_id TEXT PRIMARY KEY,
    product_name TEXT NOT NULL,
    vendor TEXT,
    affected_versions_min TEXT,
    affected_versions_max TEXT,
    fixed_version TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    published_date TEXT,
    verified INTEGER DEFAULT 1
);

-- 3. PE static security inspection records
CREATE TABLE IF NOT EXISTS pe_analysis_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    is_pe64 INTEGER DEFAULT 1,
    sections_count INTEGER NOT NULL,
    suspicious_imports_count INTEGER NOT NULL,
    findings_json TEXT,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Threat intelligence update manifest
CREATE TABLE IF NOT EXISTS threat_intel_manifest (
    feed_id TEXT NOT NULL,
    version TEXT NOT NULL,
    sequence INTEGER NOT NULL UNIQUE,
    signatures_count INTEGER NOT NULL,
    advisories_count INTEGER NOT NULL,
    publisher TEXT NOT NULL,
    signature_valid INTEGER DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (feed_id, sequence)
);
```

---

## 4. Verification Summary

| Test Module | Coverage Scope | Result |
|---|---|---|
| `test_pe_classifier.py` | PE headers, RWX sections, entropy, IAT imports, scoring, DB persistence | **5 / 5 PASS** |
| `test_patch_auditor.py` | Semantic versions, CVE matching, 7-Zip/WinRAR audit, DB persistence | **4 / 4 PASS** |
| `test_threat_intel.py` | HMAC verification, anti-rollback, replay rejection, offline import | **4 / 4 PASS** |
| `test_ransomware_improvements.py` | Entropy spike transition, simulation scenario, recovery guidance | **5 / 5 PASS** |
| Existing Regression Suite | Crypto, Authenticode, EDR, Exploit Shield, Quarantine, USB, etc. | **99 / 99 PASS** |
| **Total Automated Suite** | **Comprehensive Full System Regression** | **117 / 117 PASS** |

---

## 5. Architectural Alignment with Bitdefender GravityZone

| Bitdefender Enterprise Capability | BI Antivirus Sprint 3 Equivalent | Operational Status |
|---|---|---|
| Patch Management & Vulnerability Assessment | `SoftwarePatchAuditor` (`patch_auditor.py`) + `PatchView` | Fully Implemented & Verifiable |
| HyperDetect Machine Learning / Static PE Heuristics | `PEClassifier` (`pe_classifier.py`) + `PEClassifierView` | Deterministic Explainable Heuristics |
| Cloud / Offline Threat Intelligence Feeds | `ThreatIntelEngine` (`threat_intel.py`) | DPAPI Signed + Anti-Rollback |
| GravityZone Incident Correlation Graph & MITRE Mapping | `IncidentGraphEngine` (`incident_graph.py`) | Evidence-Categorized SOC Forensic Graph |
| Ransomware Mitigation & Canary Decoy Monitoring | `RansomwareShield` (`ransomware_shield.py`) | Entropy Spike Tracking + Simulation Harness |

*Report finalized for BI Antivirus Project — November 2026.*

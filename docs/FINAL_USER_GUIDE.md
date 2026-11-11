# BI ANTIVIRUS ENTERPRISE — OPERATOR & USER GUIDE
**Platform:** Windows 10 / 11 / Server x64  
**Project Root:** `D:\bit defender`  
**Version:** 2.0 Enterprise  

---

## 1. Overview & Interface Navigation

BI Antivirus delivers a unified defensive console engineered for high-visibility endpoint protection. The application features a dark-mode, high-contrast dashboard with responsive telemetry cards and intuitive navigation.

```
+-----------------------------------------------------------------------+
|  [BI ANTIVIRUS]               STATUS: PROTECTED           [Admin v]   |
+-----------------------------------------------------------------------+
|  [ Dashboard ]  |  REAL-TIME PROTECTION: ACTIVE                       |
|  [ Antivirus ]  |  - Signature Engine: 1,420 Active Definitions       |
|  [ EDR Alerts]  |  - Machine Learning: Calibrated HyperDetect Active  |
|  [ Quarantine]  |  - Ransomware Decoys: 12 Active Canaries Armed      |
|  [ Enterprise]  |  - USB Sentinel: Active Volume Monitoring           |
|  [ Settings  ]  |  [ Quick Scan ]    [ System Scan ]    [ Settings ]  |
+-----------------------------------------------------------------------+
```

---

## 2. Core Functional Modules

### 2.1 Running Antivirus Scans
1. **Quick Scan:** Inspects high-risk directories (`%TEMP%`, `Downloads`, Startup Run keys, running process executables). Duration: 15–30 seconds.
2. **Full System Scan:** Recursively evaluates all files across local drives against signature databases, PE structural heuristics, and machine learning models.
3. **Custom Folder Scan:** Drag-and-drop or select any directory/drive to initiate isolated targeting.

### 2.2 Quarantine Vault Management
- **AES-256 Vault:** Detected threats are neutralized immediately by moving the file into the encrypted vault (`D:\bit defender\quarantine\vault\`) with randomized filenames and an HMAC authentication tag.
- **Reviewing Threats:** Open the **Quarantine** view to inspect original file paths, detection signatures, entropy scores, and quarantine timestamps.
- **Safe Restoration:** To restore a false positive, select the record and click **Restore File**. BI Antivirus validates that the destination path contains no path traversal sequences (`..`) and refuses accidental overwrites.
- **Permanent Purge:** Clicking **Delete** permanently shreds the encrypted vault file and removes the database record.

### 2.3 Real-Time Sentinel Controls
- **Pause / Resume Protection:** Administrators can temporarily suspend real-time file event scanning from the interface (e.g., during high-throughput build operations).
- **Reputation Caching:** Repeated accesses to trusted software binaries are accelerated via the in-memory LRU reputation cache without re-scanning.
- **Exclusions:** Configure folder or extension exclusions (`.iso`, `.vdi`, `.vmdk`) under **Settings -> Exclusions** to prevent scanning overhead on virtual machine disks.

### 2.4 EDR Incident Investigation & Analyst Triage
- **Incident Graph:** When multiple suspicious events occur (e.g., an untrusted script invokes PowerShell which attempts to inject code), the EDR engine correlates them into an incident node.
- **Root Cause Analysis (RCA):** Click on any incident to view the causal process tree, parent-child relationships, command-line arguments, and MITRE ATT&CK technique tags.
- **Analyst Triage Decisions:**
  - `CONFIRM`: Marks the incident as a confirmed intrusion and escalates to network isolation.
  - `FALSE_POSITIVE`: Whitelists the behavioral sequence and updates local reputation.
  - `RESOLVE`: Closes the incident after remediation has completed.

### 2.5 Ransomware Decoy Traps & Memory Exploit Defense
- **Decoys:** The Sentinel places synthetic canary decoy files in strategic user profile folders. Any unapproved modification or deletion of a canary triggers immediate process suspension.
- **Exploit Shield:** Audits running processes for memory mitigations (DEP, ASLR, CFG) and flags unmapped RWX memory pages frequently used by shellcode injection.

### 2.6 Enterprise Administration & RBAC
- **User Roles:**
  - `Admin`: Full access to configure policies, restore files, modify exclusions, and view audit logs.
  - `Operator`: Can trigger scans, view incidents, and manage quarantine.
  - `Auditor`: Read-only access to compliance reports and SIEM audit chains.
- **Session Management:** Secure sessions enforce PBKDF2 salting, session expiration, and rapid revocation on password changes.

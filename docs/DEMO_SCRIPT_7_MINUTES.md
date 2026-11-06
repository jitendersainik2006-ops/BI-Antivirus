# BI Antivirus — 7-Minute Professional Demonstration Script

**Audience:** Sir / Technical Evaluator  
**Demonstrator:** Student / Security Engineer  
**Objective:** Present a live, evidence-based demonstration of BI Antivirus, showcasing local data sovereignty, authenticated quarantine encryption, behavioral command-line telemetry, and genuine n8n workflow integration.

---

## Demonstration Timeline Overview

```
[00:00 - 01:00]  Minute 1: Introduction, Architecture & Drive D: Containment
[01:00 - 02:00]  Minute 2: Automated Validation Suite (70/70 Tests Passing)
[02:00 - 03:15]  Minute 3: Authenticated Quarantine Vault (AES-256 + HMAC-SHA256)
[03:15 - 04:30]  Minute 4: Behavioral Sentinel & Live Process Command-Line Telemetry
[04:30 - 05:30]  Minute 5: 5-Control Windows Baseline Security Assessment
[05:30 - 06:15]  Minute 6: Genuine n8n Community Integration & Health Monitor
[06:15 - 07:00]  Minute 7: Desktop GUI Dashboard, Resource Footprint & Conclusion
```

---

## Detailed Minute-by-Minute Script

### Minute 1: Introduction & Architecture (0:00 – 1:00)
- **Spoken Talking Points:**
  > *"Good morning Sir. Today I am presenting BI Antivirus, an independently engineered Windows endpoint defense and security automation platform. Our architecture is built around three core principles: First, 100% user-space safety with zero risk of BSOD kernel crashes. Second, strict local data sovereignty where all application code, SQLite databases, and quarantine vaults reside entirely on Drive D: without cluttering Drive C:. And third, cooperative defense that complements Windows Defender rather than fighting it."*
- **Action / Command:**
  Open PowerShell in `D:\bit defender` and show project root:
  ```powershell
  cd /d "D:\bit defender"
  dir
  ```

---

### Minute 2: Automated Validation Suite (1:00 – 2:00)
- **Spoken Talking Points:**
  > *"To ensure every single advertised feature is a real, working implementation and not a simulation or UI mock, we have built a comprehensive automated test suite. Let's run it live right now."*
- **Action / Command:**
  ```powershell
  & "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" run_tests.py
  ```
- **Expected Result:**
  70 tests run across 14 modules, completing in ~3.9 seconds with **0 failures and 0 errors**.
- **Key Highlight:**
  Point out test coverage across cryptography, Authenticode, Toolhelp32 process tree, ransomware canaries, USB worms, and n8n loopback communication.

---

### Minute 3: Authenticated Quarantine Vault (2:00 – 3:15)
- **Spoken Talking Points:**
  > *"Sir, one of our major hardening accomplishments is replacing legacy XOR quarantine with enterprise-grade Authenticated Encryption: AES-256-CBC with HMAC-SHA256 in an Encrypt-then-MAC envelope, protected by Windows DPAPI. Let's inspect the quarantine vault."*
- **Action / Command:**
  ```powershell
  & "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m bi_antivirus.cli quarantine list
  ```
- **Demonstration:**
  Show the active quarantined record `Q-20261105223517-6a12cb` in `AES256_HMAC_V2` format.
  Explain the container format (`BIQ2` magic, 16-byte random IV, 32-byte constant-time HMAC tag, and AES ciphertext).
  Mention that if an attacker attempts to flip even a single bit in the vault file, HMAC verification immediately rejects the payload, preventing tamper.

---

### Minute 4: Behavioral Process Sentinel & Live Telemetry (3:15 – 4:30)
- **Spoken Talking Points:**
  > *"Next, our Behavioral Sentinel monitors running Windows processes in real-time. Unlike standard Toolhelp snapshots which only show the executable name, we integrated native `NtQueryInformationProcess(60)` to safely extract live process command lines under standard user permissions."*
- **Action / Command:**
  ```powershell
  & "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m bi_antivirus.cli behavior --limit 10
  ```
- **Key Highlight:**
  Show that process arguments are extracted in `0.23 ms`. Explain that this enables detecting LOLBin abuse (e.g. Word launching PowerShell) and ransomware staging (e.g. `vssadmin delete shadows`) before encryption occurs.

---

### Minute 5: 5-Control Windows Baseline Security Assessment (4:30 – 5:30)
- **Spoken Talking Points:**
  > *"Sir, we have also refined our vulnerability assessment module into a transparent 5-Control Windows Baseline Assessment. Rather than claiming an unsupported 100/100 posture score, we directly audit 5 concrete Windows security configurations."*
- **Action / Command:**
  ```powershell
  & "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m bi_antivirus.cli vulnerability
  ```
- **Key Highlight:**
  Walk through the 5 controls: UAC `EnableLUA`, SMBv1 protocol status, Windows Defender Firewall across all 3 profiles, RDP NLA exposure, and Windows Update service health.

---

### Minute 6: Genuine n8n Community Integration (5:30 – 6:15)
- **Spoken Talking Points:**
  > *"For autonomous diagnostics, we integrated genuine, unmodified n8n Community Edition running locally on loopback port 5679 with a segregated Task Broker on 5680. Our custom Health Monitor workflow verifies that both engine status equals PROTECTED and real-time guard is active. For safety, this workflow is persisted inactive (`active = false`) for manual testing only."*
- **Action / Command:**
  Show loopback port binding:
  ```powershell
  netstat -ano | findstr "8765 5678"
  ```
  Explain that all APIs enforce loopback-only isolation and require constant-time authenticated tokens.

---

### Minute 7: Desktop GUI Dashboard & Conclusion (6:15 – 7:00)
- **Spoken Talking Points:**
  > *"Finally, let's look at the desktop dashboard, featuring 9 fully interactive views, custom dark cyber styling, and a total runtime memory footprint of less than 35 megabytes."*
- **Action / Command:**
  Launch the GUI:
  ```powershell
  .\run_gui.bat
  ```
- **Concluding Statement:**
  > *"To summarize: BI Antivirus provides verified user-space threat detection, authenticated AES-256 quarantine encryption, live behavioral command-line telemetry, and genuine n8n automation, all completely contained on Drive D: with zero privacy leakage. Thank you, Sir. I am ready for any technical questions."*

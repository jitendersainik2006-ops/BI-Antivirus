# BI Antivirus — Project Overview

## 1. Executive Summary
**BI Antivirus** (Black Intel Cyber Defense Platform) is an advanced Windows endpoint protection system engineered from the ground up on Drive `D:\bit defender`. It provides real-time threat monitoring, streaming cryptographic signature matching, Shannon entropy heuristic analysis, Windows Authenticode digital signature verification, behavioral process tracking, ransomware canary honeypots, and removable media auditing. 

In addition, BI Antivirus natively integrates the genuine **n8n Community Edition (v2.46.5)** engine on dedicated loopback interfaces to support autonomous security orchestration and health monitoring.

---

## 2. Core Design Principles

### 2.1 Complete Drive D: Sovereignty
All project binaries, configuration files, SQLite signature and history catalogs, cryptographic quarantine vaults, logs, and workflow databases reside strictly on secondary drive `D:\bit defender` (accessible via NTFS directory junction `D:\BI-Antivirus`). The primary Windows operating system drive `C:` remains completely free from project clutter, databases, and temporary writes.

### 2.2 Coexistence with Windows Defender
BI Antivirus does not disable, replace, or weaken native Windows security controls. Instead, it operates passively alongside Windows Defender and Windows Firewall, performing independent audits, zero-trust cryptographic quarantine, and automated workflow notifications.

### 2.3 User-Space Stability (No Unsigned Kernel Drivers)
Unlike legacy antivirus software that installs uncertified kernel drivers (`.sys`) risking Windows Blue Screen of Death (BSOD) crashes, BI Antivirus operates strictly in protected user space via authenticated Win32 APIs, Windows Trust APIs (`wintrust.dll`), and Windows Data Protection API (`crypt32.dll`).

### 2.4 Authenticated Cryptographic Vault (`BIQ2`)
Isolated files are encrypted using **AES-256-CBC with HMAC-SHA256 Encrypt-then-MAC (EtM)**. The 256-bit vault master keys are protected using native **Windows DPAPI** machine-scoped encryption, ensuring that quarantined payloads cannot execute, cannot be tampered with, and can be restored bit-for-bit to their exact original bytes.

---

## 3. Technology Stack

- **Runtime:** Python 3.12 64-bit (`%LOCALAPPDATA%\Programs\Python\Python312\python.exe`)
- **Desktop Interface:** Tkinter & `tkinter.ttk` (Custom Black & Cyan Cyber Theme)
- **Local REST API:** Lightweight Python HTTP daemon (`127.0.0.1:8765`)
- **Automation Bridge:** Dedicated loopback bridge (`127.0.0.1:5678`)
- **Workflow Engine:** Genuine n8n Community Edition v2.46.5 (`127.0.0.1:5679`, Task Broker: `127.0.0.1:5680`)
- **Database Engine:** SQLite 3 with Write-Ahead Logging (WAL)
- **Cryptographic Subsystems:** Windows CNG (`bcrypt.dll`), Windows DPAPI (`crypt32.dll`), Windows Authenticode (`wintrust.dll`)

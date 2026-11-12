# BI Antivirus Enterprise — System Requirements & Compatibility Specification

**Product Name:** BI Antivirus Enterprise  
**Target Platform:** Windows 10, Windows 11, Windows Server 2019, 2022, 2025 (x64 Architecture)  
**Execution Posture:** Sovereign Windows User-Space Platform  

---

## 1. Hardware Requirements

| Component | Minimum Requirement | Recommended Specification |
| :--- | :--- | :--- |
| **Processor** | Dual-core 64-bit x86-64 CPU (1.8 GHz) | Quad-core Intel Core i5 / AMD Ryzen 5 or higher |
| **Memory (RAM)** | 2 GB Available Physical RAM | 4 GB+ System RAM (50 MB engine footprint) |
| **Disk Storage** | 500 MB Free Space on `D:\` drive | 5 GB+ for high-volume quarantine vault & forensic graphs |
| **Drive Letter** | `D:\` drive (or Windows Directory Junction) | Dedicated local SSD partition on `D:\` |
| **Display** | 1024x768 resolution | 1920x1080 (High-DPI supported) |

---

## 2. Operating System & Software Prerequisites

### 2.1 Supported Windows Releases
- **Windows 11:** Versions 21H2, 22H2, 23H2, 24H2 (x64)
- **Windows 10:** Versions 1909, 2004, 20H2, 21H1, 21H2, 22H2 (x64)
- **Windows Server:** Server 2019, Server 2022, Server 2025 (Standard / Datacenter x64)

### 2.2 Python Runtime
- **Supported Versions:** Python 3.10.x, 3.11.x, 3.12.x (64-bit)
- **Standard Library Modules Utilized:**
  - `tkinter` (GUI desktop console)
  - `sqlite3` (WAL-mode persistent databases)
  - `hashlib` & `hmac` (SHA-256, MD5, CRC32, HMAC-SHA256)
  - `ctypes` & `winreg` (Windows Win32, DPAPI, CNG, Registry APIs)
  - `threading` & `concurrent.futures` (Multi-threaded streaming scanner)
  - `socket` & `http.server` (Loopback EDR REST API)
- **Optional Dependencies (`requirements.txt`):**
  - `psutil>=5.9.0` (Live process telemetry and memory footprint auditing)

---

## 3. Privilege Levels & Security Tokens

| Operational Mode | User Privilege Level | Available Capabilities |
| :--- | :--- | :--- |
| **Standard User Mode** | Standard User (Non-Elevated) | On-demand file scanning, Shannon entropy heuristics, AES-256 quarantine vault, EDR graph correlation, Software CVE auditing, read-only system audits. |
| **Administrator Mode** | Elevated Administrator | Live Windows Firewall rule modification, WMI BitLocker status inspection, storage device write-protect registry enforcement, process mitigation enforcement. |

---

## 4. Network and Environment Boundaries
- **WAN Internet Access:** Optional. The platform operates 100% autonomously offline using local heuristics and verifiable cryptographic catalogs.
- **Loopback Ports:** Port `8765` (Local EDR REST API) is strictly bound to `127.0.0.1` (IPv4 loopback) with constant-time token verification.

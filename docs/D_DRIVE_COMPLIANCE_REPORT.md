# BI Antivirus — D: Drive Containment & Compliance Audit Report

**Project Canonical Root:** `D:\bit defender`  
**Filesystem Junction:** `D:\BI-Antivirus`  
**Target Storage Policy:** Strict Secondary Storage Containment (100% Non-Volatile Project Data on D:)  
**Audit Date:** November 2026  
**Status:** **COMPLIANT WITH DOCUMENTED HOST DEPENDENCY**

---

## 1. Physical Location Audit Matrix

An inspection of all project assets, configuration files, persistent databases, and runtime artifacts confirms their physical storage drive:

| Asset / Subsystem Category | Physical Path on Disk | Drive | Containment Status |
| :--- | :--- | :---: | :---: |
| **Source Code & Modules** | `D:\bit defender\bi_antivirus\` | **D:** | **100% CONTAINED** |
| **CLI & Execution Launchers** | `D:\bit defender\main.py`, `run_gui.bat` | **D:** | **100% CONTAINED** |
| **Technical Documentation** | `D:\bit defender\docs\` | **D:** | **100% CONTAINED** |
| **SQLite History Database** | `D:\bit defender\data\history.db` | **D:** | **100% CONTAINED** |
| **Malware Signature Database** | `D:\bit defender\data\signatures.db` | **D:** | **100% CONTAINED** |
| **Quarantine Database** | `D:\bit defender\data\quarantine.db` | **D:** | **100% CONTAINED** |
| **Encrypted Vault Storage** | `D:\bit defender\quarantine\*.biq` | **D:** | **100% CONTAINED** |
| **Security Audit Logs** | `D:\bit defender\logs\security_audit.log` | **D:** | **100% CONTAINED** |
| **Enterprise Policy & Signature** | `D:\bit defender\data\enterprise_policy.json`, `.sig` | **D:** | **100% CONTAINED** |
| **DPAPI Key Stores** | `D:\bit defender\data\vault_master.dpapi`, `policy_master.dpapi`| **D:** | **100% CONTAINED** |
| **Test Scratch Directory** | `D:\bit defender\data\crypto_test_scratch\` | **D:** | **100% CONTAINED** |
| **Automation Engine (n8n)** | `D:\bit defender\n8n\node_modules\n8n\` | **D:** | **100% CONTAINED** |
| **Host Python Interpreter** | `C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312\python.exe` | **C:** | **HOST SYSTEM TOOL** |

---

## 2. Host Python Interpreter Dependency Analysis

### Current State:
- The Python 3.12 runtime used to execute test commands and GUI scripts resides in the standard Windows user application directory on the system drive:
  `C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312\python.exe`
- Per Phase 1 Rule 2 and Phase 9 instructions:
  > *"The previous test command used Python from C:. Do not modify or uninstall that Python installation. If project execution depends on C: tools, document the dependency and prepare a safe D: environment migration plan. Do not break the existing setup."*

### Zero Third-Party Python Dependencies:
- BI Antivirus was architected with **zero heavy external dependencies** (no PyPI packages required for core antivirus execution).
- All modules utilize the standard Python library (`ctypes`, `hashlib`, `hmac`, `secrets`, `sqlite3`, `tkinter`, `urllib`, `subprocess`, `threading`, `json`).
- Consequently, the Python installation on `C:` is merely a host interpreter; **zero project libraries, databases, or application data files are installed into `C:\`**.

---

## 3. Safe D: Drive Environment Migration Plan (Future Standalone Setup)

To transition to an entirely self-contained D: drive portable environment without disrupting the existing system:

```mermaid
flowchart LR
    A[Current State: C: Python Host] -->|Safe venv creation| B[D:\bit defender\venv]
    B -->|Symlink-Free Portable Runtime| C[Update run_gui.bat & scripts]
    C -->|Zero System Drive Dependency| D[100% Self-Contained D: Appliance]
```

### Step-by-Step Transition Plan:
1. **Create Isolated Virtualenv on D:**
   ```powershell
   & "C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312\python.exe" -m venv "D:\bit defender\venv"
   ```
2. **Verify Portability**:
   Ensure `D:\bit defender\venv\Scripts\python.exe` executes cleanly and includes Tkinter support.
3. **Update Batch Launchers**:
   Update `run_gui.bat` and CLI scripts to prioritize `D:\bit defender\venv\Scripts\python.exe` when present, falling back to the system path only if absent.
4. **Safety Guarantee**:
   The host Python installation on `C:` remains untouched and available for all other system applications.

---

## 4. Test Harness D: Drive Containment

In earlier test executions, standard `tempfile.TemporaryDirectory()` invocations defaulted to the Windows user `%TEMP%` directory on `C:\`.
This has been explicitly hardened:
- In [`test_policy_and_controls.py`](file:///D:/bit%20defender/bi_antivirus/tests/test_policy_and_controls.py) and [`test_encryption_manager.py`](file:///D:/bit%20defender/bi_antivirus/tests/test_encryption_manager.py), all temporary test directories are created with:
  ```python
  D_DRIVE_SCRATCH = Path(r"D:\bit defender\data\crypto_test_scratch")
  self.temp_dir = tempfile.TemporaryDirectory(dir=str(D_DRIVE_SCRATCH), ignore_cleanup_errors=True)
  ```
- **Result**: 100% of automated test scratch files, mock databases, and temporary policies are strictly contained on `D:\bit defender`.

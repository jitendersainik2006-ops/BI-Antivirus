# BI ANTIVIRUS ENTERPRISE — TROUBLESHOOTING & RECOVERY MANUAL
**Project Root:** `D:\bit defender` (Junction: `D:\BI-Antivirus`)  
**Target Platform:** Windows 10, Windows 11, Windows Server 2019/2022/2025 (x64)  
**Version:** 2.0 Enterprise Production Release  

---

## 1. GUI Dashboard Does Not Appear on Screen

### Symptoms:
Running `python main.py` or double-clicking `run_gui.bat` shows python in Task Manager, but no window is visible.

### Cause:
Windows Session Isolation / Window Station Security prevents background services or non-interactive shells from drawing windows onto the interactive user desktop (`WinSta0\Default`).

### Resolution:
Launch the GUI directly from your logged-in interactive desktop session:
* **File Explorer:** Double-click `run_gui.bat` in the repository root.
* **PowerShell:** `cd "D:\bit defender"; .\run_gui.bat`
* **Command Prompt:** `cd /d "D:\bit defender" && run_gui.bat`

---

## 2. Python Architecture Warning (32-bit vs 64-bit)

### Symptoms:
The setup wizard or compatibility auditor warns about WOW64 architecture.

### Cause:
32-bit Python installations cannot audit 64-bit Win32 processes and will encounter `PAGE_FAULT` or truncation when inspecting 64-bit memory addresses in Exploit Shield.

### Resolution:
Install 64-bit Python 3.10, 3.11, or 3.12:
```powershell
python -c "import struct; print(struct.calcsize('P') * 8)"
# Expected output: 64
```

---

## 3. Tkinter Not Installed on Custom Python

### Symptoms:
Launching GUI fails with `ModuleNotFoundError: No module named '_tkinter'`.

### Cause:
Minimal or embedded Python distributions (such as MS Store Python or certain custom pyenv builds) omit Tcl/Tk support.

### Resolution:
1. Re-run the official standard Python installer from https://www.python.org.
2. Select **Modify** and ensure the checkbox for **tcl/tk and IDLE** is enabled.
3. Alternatively, BI Antivirus operates fully in CLI mode: `python main.py status`.

---

## 4. Permission Denied on Host Firewall Manipulation

### Symptoms:
Running firewall isolation fails or status reports `Audit-Only (Visibility Mode)`.

### Cause:
Host network rule modification via `netsh advfirewall` requires Windows Administrator privileges (`SeSecurityPrivilege` / token elevation).

### Resolution:
Right-click your terminal or PowerShell and select **Run as Administrator**. When run without elevation, BI Antivirus safely operates in Audit-Only mode without disrupting network traffic.

---

## 5. Automated Tests: Network Safety During Isolation Tests

### Symptoms:
You want to verify that automated testing does not drop network connections on your workstation.

### Resolution:
The automated test runner sets `BI_TEST_MODE=1` and enforces `dry_run=True` in all firewall test cases. Live netsh commands are never sent to the operating system during automated tests. Additionally, [`data/emergency_firewall_restore.bat`](file:///D:/bit%20defender/data/emergency_firewall_restore.bat) is pre-generated for offline recovery.

---

## 6. REST API Returns 401 Unauthorized

### Symptoms:
API calls to `http://127.0.0.1:8000/api/v1/status` return HTTP `401 Unauthorized`.

### Cause:
Missing or incorrect `X-BI-API-Key` HTTP header.

### Resolution:
Pass the valid token from `data/api_key.txt` via header:
```powershell
$token = Get-Content "data\api_key.txt"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/status" -Headers @{"X-BI-API-Key"=$token}
```

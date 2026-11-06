# BI Antivirus — Troubleshooting Guide

Common issues, diagnostic procedures, and safe resolutions.

---

## 1. GUI Dashboard Does Not Appear on Screen

### Symptoms:
Running a command starts Python in Task Manager (PID exists), but no window is visible on your monitor.

### Cause:
Windows Session Isolation / Window Station Security prevents background services or tools from drawing windows onto the interactive user desktop (`WinSta0\Default`).

### Resolution:
Launch the GUI directly from your logged-in desktop session using **ONE** of these methods:
- **File Explorer:** Double-click `D:\bit defender\run_gui.bat`.
- **PowerShell:** Run `Set-Location "D:\bit defender"; .\run_gui.bat`.
- **CMD:** Run `cd /d "D:\bit defender" && run_gui.bat`.

---

## 2. Custom Scan Shows 0 Files or Does Not Start

### Symptoms:
Selecting a folder and clicking scan leaves the file ticker at "Idle" with 0 files scanned.

### Cause:
Earlier versions had a method mismatch where `FileScanner` lacked `scan_custom`. This has been permanently resolved with `scan_custom` routing to `scan_path` and worker exception handling.

### Resolution:
Ensure you are running the latest build. Close any open dashboard instances and relaunch `run_gui.bat`.

---

## 3. Real-Time Guard Flags 0-Byte Temporary Files

### Symptoms:
Logs show detections of `Empty-Payload-ZeroByte` on temporary `.dat` lock files.

### Cause:
Legacy seed database contained the empty-string SHA-256 hash.

### Resolution:
This is resolved in the current engine. Zero-byte files (`stat().st_size == 0`) are immediately short-circuited as `CLEAN`, and the deprecated hash is automatically purged on initialization.

---

## 4. REST API Returns 401 Unauthorized

### Symptoms:
API calls to `http://127.0.0.1:8765/api/v1/status` return HTTP `401 Unauthorized`.

### Cause:
Missing or incorrect `X-BI-API-Key` HTTP header.

### Resolution:
Ensure requests pass the valid token from `D:\bit defender\data\api_key.txt` via header:
`X-BI-API-Key: <token>`

# BI Antivirus — User Guide & Operations Manual

## 1. Desktop Dashboard User Interface

The desktop dashboard provides centralized, intuitive visibility into endpoint protection:

### Navigation Sidebar
- **🛡️ Dashboard (Overview)**: Displays current protection posture (`PROTECTED`, `WARNING`, `THREAT_DETECTED`), real-time sentinels telemetry bar, quick metrics (signatures, scanned files, threats, quarantined items), and one-click scan launch cards.
- **🔍 Scan Center**: Choose between Quick Scan (critical Windows directories), Full Scan (deep drive traversal), or Custom Target Scan. Features real-time progress indicators, scan rate ($f/s$), and detection log.
- **📦 Quarantine Vault**: View isolated threats, threat families, detection timestamps, and cryptographic vault formats (`AES256_HMAC_V2` or legacy `XOR_V1`). Provides user-confirmed **Restore** and **Purge** actions.
- **📜 Threat History**: Searchable SQLite audit log of all identified threat events, file hashes, timestamps, and automated remediation actions.
- **🌐 Real-Time & Web**: Toggle real-time filesystem directory polling, manage custom monitored folders, and query URLs against local phishing/TLD reputation rules.
- **🔥 Firewall & Network**: Read-only inspection of Windows Defender Firewall profiles (Domain, Private, Public) and active network socket connection auditing.
- **⚡ Automation & Voice**: Monitor n8n Community integration status, inspect loopback endpoints, and test sanitized text-to-speech voice announcements.
- **⚙️ Settings & Exclusions**: Manage directory and extension exclusions, adjust scan heuristics, and configure alert policies.
- **📊 Security Reports**: Review, export, and generate markdown security audit assessments directly on the D: drive.

---

## 2. Command-Line Interface (CLI) Reference

The CLI provides headless, scriptable command execution via `run_cli.bat` or `main.py`:

### System Status
```cmd
run_cli.bat status
```
Displays engine status, signature counts, definitions version, total scanned files, and quarantine count.

### Running File Scans
```cmd
:: Quick Scan of Windows hotspots
run_cli.bat scan --quick

:: Full system scan of all drives
run_cli.bat scan --full

:: Custom folder or file scan
run_cli.bat scan --path "D:\my_folder"
```

### Managing the Quarantine Vault
```cmd
:: List all quarantined records
run_cli.bat quarantine list

:: Reversibly restore a quarantined file back to its original location
run_cli.bat quarantine restore Q-20261105223517-6a12cb

:: Restore to a custom safe directory
run_cli.bat quarantine restore Q-20261105223517-6a12cb --to "D:\safe_output"

:: Permanently purge an item from the vault
run_cli.bat quarantine purge Q-20261105223517-6a12cb
```

### 5-Control Windows Baseline Security Assessment
```cmd
run_cli.bat vulnerability
```
Audits 5 core Windows security configuration controls: UAC status, SMBv1 deprecation, Windows Defender Firewall status, Remote Desktop exposure, and Windows Update service health.

### Inspecting Running Process Behavior
```cmd
run_cli.bat behavior --limit 30
```
Extracts process hierarchies and executable command lines using `NtQueryInformationProcess(60)` to identify LOLBin exploitation or ransomware staging.

### Ransomware Honeypot & Canary Inspection
```cmd
run_cli.bat ransomware
```
Displays status of deployed canary decoy traps and mutation burst counters.

### Removable USB Drive Audit
```cmd
:: Audit all mounted removable drives
run_cli.bat usb

:: Audit a specific drive letter
run_cli.bat usb --scan E:
```

### Authenticode Digital Signature Verification
```cmd
run_cli.bat authenticode "C:\Windows\System32\notepad.exe"
```
Directly verifies digital certificate validity via Windows `WinVerifyTrust`.

### Web Reputation Query
```cmd
run_cli.bat web "https://suspicious-domain-example.top/login"
```

---

## 3. Safe Testing with Harmless Synthetic Files

Never test antivirus software with live malware. BI Antivirus supports standard synthetic testing:

### EICAR Standard Test String
The industry standard EICAR test string evaluates signature recognition without danger:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
Creating a file with this text will trigger `EICAR-Test-File (Standard Test String)` recognition, demonstrating instant detection, alerting, and quarantine isolation.

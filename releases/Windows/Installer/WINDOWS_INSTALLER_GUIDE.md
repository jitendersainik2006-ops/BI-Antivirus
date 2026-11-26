# BI Antivirus Enterprise — Windows Laptop Installer Guide
**Black Intel Cyber Defense Platform**

## Overview
`BI_Antivirus_Enterprise_v1.0.0_Setup.exe` is the official, one-click Windows installer for **BI Antivirus Enterprise**. It provides a frictionless setup experience for Windows laptops and workstations, with zero unnecessary administrator elevation prompts, automatic prerequisite detection, Start Menu and Desktop shortcuts, an interactive first-run onboarding wizard, and safe uninstallation with quarantine vault retention.

---

## 1. Quick Installation (One-Click)

1. Double-click `BI_Antivirus_Enterprise_v1.0.0_Setup.exe`.
2. Follow the setup wizard prompts:
   - **Destination:** Default location is `{LocalAppData}\Programs\Black Intel\BI Antivirus` (No Administrator prompt needed) or `C:\Program Files\Black Intel\BI Antivirus` (if elevated).
   - **Shortcuts:** Checked by default for Desktop and Start Menu.
   - **Prerequisites:** Setup automatically checks for Python 3.10+ and Windows 10/11 x64.
3. Click **Install**.
4. Check **Launch BI Antivirus Enterprise** and click **Finish**.
5. The **Universal First-Run Setup Wizard** will guide you through baseline security configuration in under 60 seconds!

---

## 2. Silent & Enterprise Deployment (Command Line)

For network administrators and fleet deployment scripts:

```powershell
# Silent installation with default settings (no prompts)
.\BI_Antivirus_Enterprise_v1.0.0_Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# Custom installation directory
.\BI_Antivirus_Enterprise_v1.0.0_Setup.exe /DIR="C:\Security\BIAntivirus" /VERYSILENT /NORESTART

# Installation with detailed debug logging
.\BI_Antivirus_Enterprise_v1.0.0_Setup.exe /LOG="C:\Temp\bi_install.log" /VERYSILENT
```

---

## 3. First-Run Setup Wizard

Upon first launch, the wizard presents a simple 4-step configuration:
1. **Welcome:** Introduction to Black Intel Cyber Defense.
2. **Device Compatibility Check:** Automatically verifies system architecture, memory, and antivirus coexistence.
3. **Protection Profile:** Choose between **Smart Shield** (Balanced, silent, zero false alarms) and **Fortress Shield** (Maximum enterprise defense with strict heuristics and USB auto-scan).
4. **Completion:** Displays active green **PROTECTED** status and initiates an initial baseline scan.

---

## 4. Upgrading & Data Preservation

- Installing a newer version over an existing installation automatically preserves your:
  - Encrypted Quarantine Vault (`data/quarantine/`)
  - Threat detection history (`data/scan_history.db`)
  - Custom exclusion rules and preferences (`data/settings.json`)
- Upgrades perform an in-place atomic update with zero data loss.

---

## 5. Uninstallation & Removal

- Open **Windows Settings > Apps > Installed apps**, find **BI Antivirus Enterprise**, and click **Uninstall**.
- Or run the uninstaller directly from the Start Menu: **BI Antivirus Enterprise > Uninstall**.
- During uninstallation, the wizard asks whether you wish to retain your encrypted Quarantine Vault for safety. Choosing "Yes" ensures that potentially valuable quarantined files remain safely locked on disk in case of future reinstallation.

---

## 6. Package Checksum

```text
File: BI_Antivirus_Enterprise_v1.0.0_Setup.exe
SHA-256: 5cab38598098f39695d49d7650d74a82f4fd3fb8531c1971ecdd7ecf68d21123
```

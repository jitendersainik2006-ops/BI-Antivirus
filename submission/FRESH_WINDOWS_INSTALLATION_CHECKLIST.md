# BI ANTIVIRUS ENTERPRISE — FRESH WINDOWS INSTALLATION CHECKLIST

This checklist guides Sir or any independent evaluator through verifying BI Antivirus Enterprise on a freshly installed or separate Windows workstation.

---

## 1. Workstation Pre-flight Verification

| Step | Verification Check | Expected Condition | Checked |
| :---: | :--- | :--- | :---: |
| **1.1** | **Operating System** | Windows 10 (x64), Windows 11 (x64), or Windows Server 2019+ | [ ] |
| **1.2** | **System Architecture** | 64-bit operating system (`x86_64` / `AMD64`) | [ ] |
| **1.3** | **Python Installation** | Python 3.12 (specifically tested on 3.12.10 64-bit).<br/>Check: `python --version` returns `Python 3.12.x`. | [ ] |
| **1.4** | **Python PATH Binding** | `python` and `pip` accessible directly from PowerShell or Command Prompt. | [ ] |
| **1.5** | **Storage Drive Space** | Minimum 500 MB free storage on target drive (D: preferred, or any fixed drive). | [ ] |
| **1.6** | **Node.js / n8n Check** | **OPTIONAL**: Verify whether Node.js is needed. Confirm that core AV functions operate without Node.js. | [ ] |

---

## 2. Extraction & Installation Steps

### Step 2.1: Extract Archive
* Extract `BI_Antivirus_Enterprise_v1.0.0_Portable.zip` into your chosen directory (e.g., `D:\BI-Antivirus` or `D:\bit defender`).
* Verify that the extracted root contains `main.py`, `run_gui.bat`, `run_demo.bat`, `run_tests.bat`, `setup_windows.bat`, `requirements.txt`, and `.env.example`.

### Step 2.2: Install Python Dependencies
Open PowerShell or Command Prompt as standard user in the project root:
```powershell
pip install -r requirements.txt
```
*Expected Output:* `Successfully installed psutil-...` (or `Requirement already satisfied`).

### Step 2.3: Execute Windows Setup Wizard
Run the one-click setup script:
```powershell
.\setup_windows.bat
```
*Expected Output:*
* Detects Python runtime.
* Creates `data/`, `logs/`, `quarantine/`, `reports/` directories.
* Initializes `signatures.db` and seeds 18 threat signatures.
* Verifies SQLite WAL mode and database integrity (`PRAGMA integrity_check: ok`).
* Displays: `SETUP COMPLETED SUCCESSFULLY!`

---

## 3. Hands-On Functional Verification Checklist

| Step | Test Objective | Execution Command | Success Criteria | Checked |
| :---: | :--- | :--- | :--- | :---: |
| **3.1** | **Launch Desktop GUI** | `.\run_gui.bat` | Tkinter dark cyber UI launches with 13 working views. Title: "BI Antivirus - Cyber Defense Platform". | [ ] |
| **3.2** | **GUI Quick Scan** | Click "Quick Scan" button in GUI | Traverses system directories, scans files, logs results to history database. | [ ] |
| **3.3** | **Live Safe Demo** | `.\run_demo.bat` | Completes 10/10 synthetic stages: threat generation, hash lookup, quarantine, rollback, EDR graph correlation. | [ ] |
| **3.4** | **Unit Test Suite** | `.\run_tests.bat` | **276 / 276 tests pass** across 44 suites with 0 failures, 0 errors, 0 skipped. | [ ] |
| **3.5** | **Clean Slate Audit** | `python scripts\verify_clean_acceptance.py` | 7 / 7 acceptance gates pass in isolated local directory (`data\clean_acceptance_test`). | [ ] |
| **3.6** | **CLI Status Query** | `.\run_cli.bat status` | Prints structured CLI status: Engine: ONLINE, DB: signatures.db (18 signatures). | [ ] |
| **3.7** | **Safe Uninstallation** | `.\uninstall_windows.bat` | Interactive prompt displays Mode 1 (Standard Preserve) and Mode 2 (Purge). | [ ] |

---

## 4. Verification Notes for Evaluators

1. **Working Directory Integrity:** All batch files automatically resolve `%~dp0` and switch directory to the script root. If invoking python scripts directly from terminal, ensure the current working directory is the project root.
2. **Path Portability:** All internal paths dynamically auto-discover the repository root via `Path(__file__).resolve().parent`. There is zero dependency on fixed developer user profile paths.
3. **SmartScreen Notice:** Because this evaluation package is unsigned, Windows SmartScreen may present a blue prompt ("Windows protected your PC") on clean systems. Click *"More info"* -> *"Run anyway"* to evaluate.
4. **Coexistence:** BI Antivirus does not disable or conflict with Windows Defender or third-party endpoint security software.

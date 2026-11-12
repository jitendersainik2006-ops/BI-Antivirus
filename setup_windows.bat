@echo off
setlocal enabledelayedexpansion
title BI Antivirus Enterprise - Windows Setup Wizard
cd /d "%~dp0"

echo ========================================================================
echo        BI Antivirus Enterprise - Windows Setup Wizard
echo        Platform: Windows 10 / 11 / Server 2019+ (x64)
echo ========================================================================
echo.

:: Detect Python executable
set PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

echo [*] Checking Python runtime...
"%PYTHON_EXE%" --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] ERROR: Python 3 was not found in PATH or standard install directory.
    echo Please install Python 3.10, 3.11, or 3.12 (64-bit) from https://www.python.org
    pause
    exit /b 1
)

echo [+] Python runtime verified:
"%PYTHON_EXE%" --version

echo.
echo [*] Installing / verifying dependencies from requirements.txt...
"%PYTHON_EXE%" -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [!] Warning: pip install encountered an issue, proceeding with standard library...
)

echo.
echo [*] Running automated environment setup and database initialization...
"%PYTHON_EXE%" scripts\install_windows.py
if %ERRORLEVEL% neq 0 (
    echo [!] Setup wizard reported an issue. Review logs in logs\
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo   SETUP COMPLETED SUCCESSFULLY!
echo ========================================================================
echo.
echo Next Steps:
echo   1. Launch Desktop GUI Console: run_gui.bat
echo   2. Run Live Harmless Demo:     run_demo.bat
echo   3. Run Automated Test Suite:   run_tests.bat
echo   4. Package Standalone Bundle:  python scripts\package_windows.py
echo   5. Safe Windows Uninstaller:   uninstall_windows.bat
echo.
pause

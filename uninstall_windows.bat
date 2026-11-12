@echo off
setlocal enabledelayedexpansion
title BI Antivirus Enterprise - Windows Uninstaller
cd /d "%~dp0"

echo ========================================================================
echo        BI Antivirus Enterprise - Windows Uninstaller
echo        Platform: Windows 10 / 11 / Server 2019+ (x64)
echo ========================================================================
echo.

set PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

echo Select uninstallation mode:
echo   [1] Standard Uninstall (Preserve databases, quarantine vault, and reports)
echo   [2] Complete Purge (Remove all local databases, quarantine, and logs)
echo   [3] Cancel
echo.
set /p CHOICE="Enter choice [1, 2, or 3]: "

if "%CHOICE%"=="1" (
    echo.
    echo [*] Running standard uninstallation...
    "%PYTHON_EXE%" scripts\uninstall_windows.py --yes
) else if "%CHOICE%"=="2" (
    echo.
    echo [!] WARNING: You have selected to purge all local databases, vaults, and reports.
    set /p CONFIRM="Are you sure you want to permanently delete all data? (yes/no): "
    if /i "!CONFIRM!"=="yes" (
        "%PYTHON_EXE%" scripts\uninstall_windows.py --purge-data --yes
    ) else (
        echo Uninstallation cancelled by user.
    )
) else (
    echo Uninstallation cancelled.
)

echo.
pause

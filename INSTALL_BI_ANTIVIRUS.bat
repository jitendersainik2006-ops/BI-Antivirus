@echo off
setlocal
cd /d "%~dp0"

:: ============================================================================
:: BI Antivirus Enterprise — Universal Android Installation Assistant
:: Black Intel Cyber Defense Platform
:: Compatible with all Android phones/tablets (Samsung, Pixel, Xiaomi, vivo,
:: iQOO, OnePlus, OPPO, realme, Motorola, Nothing, and generic Android 8.0+)
:: ============================================================================

title BI Antivirus Enterprise — Universal Android Installer

set "PY_EXE="
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"

if not defined PY_EXE (
    where py >nul 2>&1
    if not errorlevel 1 set "PY_EXE=py"
)
if not defined PY_EXE (
    where python >nul 2>&1
    if not errorlevel 1 set "PY_EXE=python"
)

if not defined PY_EXE (
    echo.
    echo ======================================================================
    echo  BI ANTIVIRUS ENTERPRISE — PREREQUISITE NOTICE
    echo ======================================================================
    echo  Python 3.10 or higher is required to run the automated installer.
    echo.
    echo  To install Python automatically, open PowerShell and run:
    echo    winget install Python.Python.3.12
    echo ======================================================================
    echo.
    pause
    exit /b 1
)

if exist "%~dp0scripts\universal_android_installer.py" (
    "%PY_EXE%" "%~dp0scripts\universal_android_installer.py"
) else if exist "%~dp0..\..\scripts\universal_android_installer.py" (
    "%PY_EXE%" "%~dp0..\..\scripts\universal_android_installer.py"
) else (
    "%PY_EXE%" scripts\universal_android_installer.py
)

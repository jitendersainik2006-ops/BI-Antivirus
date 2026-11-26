@echo off
setlocal
cd /d "%~dp0"

:: ============================================================================
:: BI Antivirus Enterprise — Wireless / QR Installation Assistant
:: Black Intel Cyber Defense Platform — Secure Local Network Transfer
:: ============================================================================

title BI Antivirus Enterprise — Wireless QR Code Installer

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
    echo Python 3.10 or higher is required.
    pause
    exit /b 1
)

"%PY_EXE%" scripts\qr_apk_server.py

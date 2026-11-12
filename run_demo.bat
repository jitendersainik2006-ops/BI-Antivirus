@echo off
title BI Antivirus Enterprise - Live Demonstration Lifecycle
cd /d "%~dp0"

set PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

echo Starting BI Antivirus Enterprise 10-Stage Harmless Live Demonstration...
echo Execution Mode: Safe Synthetic Validation (No Live Malware, No Firewall Cuts)
echo.

"%PYTHON_EXE%" scripts\demo_full_lifecycle.py
echo.
pause

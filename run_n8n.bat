@echo off
title BI Antivirus - Local n8n Automation Bridge
cd /d "%~dp0"
echo ======================================================================
echo    BI ANTIVIRUS - LOCAL N8N AUTOMATION BRIDGE DAEMON
echo    Binding: http://127.0.0.1:5678 (Loopback Only)
set PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)
"%PYTHON_EXE%" -m bi_antivirus.api.n8n_daemon
pause

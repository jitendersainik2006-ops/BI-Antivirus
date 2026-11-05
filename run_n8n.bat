@echo off
title BI Antivirus - Local n8n Automation Bridge
cd /d "%~dp0"
echo ======================================================================
echo    BI ANTIVIRUS - LOCAL N8N AUTOMATION BRIDGE DAEMON
echo    Binding: http://127.0.0.1:5678 (Loopback Only)
echo ======================================================================
"C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312\python.exe" -m bi_antivirus.api.n8n_daemon
pause

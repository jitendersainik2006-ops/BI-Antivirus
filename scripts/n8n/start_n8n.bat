@echo off
title BI Antivirus - Start Genuine n8n (Port 5679)
cd /d "D:\bit defender\scripts\n8n"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\bit defender\scripts\n8n\start_n8n.ps1"
pause

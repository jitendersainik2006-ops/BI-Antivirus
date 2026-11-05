@echo off
title BI Antivirus - Stop Genuine n8n (Port 5679)
cd /d "D:\bit defender\scripts\n8n"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\bit defender\scripts\n8n\stop_n8n.ps1"
pause

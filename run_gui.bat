@echo off
title BI Antivirus - Desktop Dashboard
cd /d "%~dp0"
set PYTHON_EXE=C:\Users\jitendersaini2006\AppData\Local\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)
echo Starting BI Antivirus Cyber Defense Dashboard...
start "" "%PYTHON_EXE%" main.py

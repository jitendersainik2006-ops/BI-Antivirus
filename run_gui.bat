@echo off
title BI Antivirus - Desktop Dashboard
cd /d "%~dp0"
set PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)
echo Starting BI Antivirus Cyber Defense Dashboard...
start "" "%PYTHON_EXE%" main.py

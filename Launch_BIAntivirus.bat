@echo off
setlocal
cd /d "%~dp0"

:: BI Antivirus Enterprise - Windows Desktop Launcher
:: Black Intel Cyber Defense Platform

set "PY_EXE="
if exist "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe"
if not defined PY_EXE if exist "%ProgramFiles%\Python314\pythonw.exe" set "PY_EXE=%ProgramFiles%\Python314\pythonw.exe"
if not defined PY_EXE if exist "%ProgramFiles%\Python312\pythonw.exe" set "PY_EXE=%ProgramFiles%\Python312\pythonw.exe"
if not defined PY_EXE if exist "%ProgramFiles%\Python311\pythonw.exe" set "PY_EXE=%ProgramFiles%\Python311\pythonw.exe"

if not defined PY_EXE (
    where pythonw >nul 2>&1
    if not errorlevel 1 set "PY_EXE=pythonw"
)
if not defined PY_EXE (
    where python >nul 2>&1
    if not errorlevel 1 set "PY_EXE=python"
)

if not defined PY_EXE (
    echo.
    echo ======================================================================
    echo  BI ANTIVIRUS ENTERPRISE - PREREQUISITE NOTICE
    echo ======================================================================
    echo  Python 3.10 or higher is required to launch the desktop application.
    echo.
    echo  To install Python automatically, open PowerShell and run:
    echo    winget install Python.Python.3.12
    echo ======================================================================
    echo.
    pause
    exit /b 1
)

start "" "%PY_EXE%" main.py --gui

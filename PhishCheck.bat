@echo off
rem python -m phishcheck --guiDouble-click to open the PhishCheck drag-and-drop window in your browser.
rem Runs through python.exe (signed) rather than the generated phishcheck.exe launcher,
rem which Windows Smart App Control / Application Control blocks because it is unsigned.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo PhishCheck is not installed yet. In this folder run:
    echo     python -m venv .venv
    echo     .venv\Scripts\python -m pip install -e .
    pause
    exit /b 1
)
title PhishCheck
".venv\Scripts\python.exe" -m phishcheck --gui %*
if errorlevel 1 pause

@echo off
title Aegis Security
cd /d "%~dp0"

rem Relaunch elevated so admin-gated features (boot-time scan, HKLM startup
rem entries, protected junk paths) work. Comment out to run unprivileged.
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

where pythonw >nul 2>&1
if %errorLevel%==0 (
    start "" pythonw aegis.py
) else (
    python aegis.py
)

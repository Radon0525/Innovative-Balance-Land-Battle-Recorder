@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment is missing. See README.md.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" recorder.py
if errorlevel 1 pause

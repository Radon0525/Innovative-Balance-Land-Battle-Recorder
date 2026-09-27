@echo off
setlocal
cd /d "%~dp0"
py -3.12 -c "import sys; assert sys.maxsize > 2**32" >nul 2>&1
if errorlevel 1 (
  echo Install Python 3.12 for Windows, 64-bit, with the Python launcher.
  echo https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -c "import tkinter, frida, pefile, capstone"
if errorlevel 1 goto failed
echo Setup complete. Open the launcher to start recording.
exit /b 0
:failed
echo Setup failed. Please check the error above.
pause
exit /b 1

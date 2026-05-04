@echo off
setlocal
title AI-IDS NIGHTWATCH — Backend Server

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   AI-IDS NIGHTWATCH  —  Backend Server          ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: ── Check for Administrator rights ───────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] This script must be run as Administrator!
    echo          Right-click start_backend.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)
echo  [OK] Running as Administrator.

:: ── Open firewall ports so Windows does not block WebSocket / API ─────────────
echo  [INFO] Adding Windows Firewall rules for ports 8000 and 5173...

netsh advfirewall firewall add rule ^
  name="AIPS Backend Port 8000" ^
  dir=in action=allow protocol=TCP localport=8000 ^
  >nul 2>&1

netsh advfirewall firewall add rule ^
  name="AIPS Frontend Port 5173" ^
  dir=in action=allow protocol=TCP localport=5173 ^
  >nul 2>&1

echo  [OK] Firewall rules added (or already exist).
echo.

:: ── Change to backend directory ───────────────────────────────────────────────
cd /d "%~dp0backend"
if %errorlevel% neq 0 (
    echo  [ERROR] Could not find the backend\ directory next to this .bat file.
    pause
    exit /b 1
)

:: ── Install dependencies ──────────────────────────────────────────────────────
echo  [INFO] Checking Python dependencies (this may take a moment on first run)...
pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo  [ERROR] pip install failed. Check your Python installation and requirements.txt.
    pause
    exit /b 1
)
echo  [OK] Dependencies satisfied.
echo.

:: ── Start Uvicorn ─────────────────────────────────────────────────────────────
echo  [INFO] Starting FastAPI server on http://localhost:8000
echo  [INFO] Press Ctrl+C to stop.
echo.

uvicorn main:app --reload --port 8000 --host 0.0.0.0
set EXIT_CODE=%errorlevel%

:: If we reach here, uvicorn exited (crashed or Ctrl+C)
echo.
if %EXIT_CODE% neq 0 (
    echo  [ERROR] Server exited with code %EXIT_CODE%.
    echo          Check the output above for the full error traceback.
) else (
    echo  [INFO] Server stopped cleanly.
)
echo.
pause
endlocal

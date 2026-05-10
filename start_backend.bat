@echo off
setlocal

:: Capture all paths BEFORE any cd command
set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%~dp0backend"
set "DEPS_FLAG=%~dp0deps_installed.txt"

title AI-IDS NIGHTWATCH - Backend Server

echo.
echo  AI-IDS NIGHTWATCH  -  Backend Server
echo  ================================================
echo.

:: Check for Administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] This script must be run as Administrator!
    echo          Right-click start_backend.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)
echo  [OK] Running as Administrator.

:: Open firewall ports
echo  [INFO] Adding Windows Firewall rules for ports 8000 and 5173...
netsh advfirewall firewall add rule name="AIPS Backend Port 8000" dir=in action=allow protocol=TCP localport=8000 >nul 2>&1
netsh advfirewall firewall add rule name="AIPS Frontend Port 5173" dir=in action=allow protocol=TCP localport=5173 >nul 2>&1
echo  [OK] Firewall rules added (or already exist).
echo.

:: Change to backend directory
cd /d "%BACKEND_DIR%"
if %errorlevel% neq 0 goto :cd_error

:: Install dependencies only once
if exist "%DEPS_FLAG%" goto :deps_ok

echo  [INFO] Installing Python dependencies (first run only)...
pip install -r requirements.txt -q
if %errorlevel% neq 0 goto :pip_error
echo done > "%DEPS_FLAG%"
echo  [OK] Dependencies installed.
goto :start_server

:deps_ok
echo  [OK] Dependencies already satisfied.

:start_server
echo.
echo  [INFO] Starting FastAPI server on http://localhost:8000
echo  [INFO] Press Ctrl+C to stop.
echo.

python -m uvicorn main:app --reload --port 8000 --host 0.0.0.0

echo.
echo  [INFO] Server stopped.
echo.
pause
endlocal
exit /b 0

:cd_error
echo  [ERROR] Could not find the backend directory: %BACKEND_DIR%
pause
exit /b 1

:pip_error
echo  [ERROR] pip install failed. Check your Python installation.
pause
exit /b 1

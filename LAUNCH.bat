@echo off
setlocal

:: ── Self-elevate to Administrator via PowerShell UAC prompt ──────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command ^
      "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b 0
)

:: Ensure we are in the script's directory
cd /d "%~dp0"

:: ── Open firewall ports ───────────────────────────────────────────────────────
netsh advfirewall firewall add rule name="AIPS Backend Port 8000" dir=in action=allow protocol=TCP localport=8000 >nul 2>&1
netsh advfirewall firewall add rule name="AIPS Frontend Port 5173" dir=in action=allow protocol=TCP localport=5173 >nul 2>&1

:: ── Start the backend in its own visible terminal window ─────────────────────
echo  [1/3] Starting backend server...
start "AIPS Backend" "%~dp0start_backend.bat"

:: ── Poll port 8000 until the backend is ready (TCP check via PowerShell) ──────
echo  [2/3] Waiting for backend to be ready on port 8000...
:wait_loop
powershell -NoProfile -Command ^
  "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1',8000); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 1 /nobreak >nul
    goto wait_loop
)
echo  [OK] Backend is ready.

:: ── Start the frontend in its own terminal window ────────────────────────────
echo  [3/3] Starting frontend dev server...
cd /d "%~dp0frontend"
start "AIPS Frontend" cmd /k "npm run dev"

:: ── Give Vite ~3 seconds to bind, then open the browser ─────────────────────
timeout /t 3 /nobreak >nul
start "" "http://localhost:5173"

echo.
echo  Both servers are running. You can close this window.
echo.
endlocal

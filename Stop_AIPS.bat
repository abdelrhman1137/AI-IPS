@echo off
echo Requesting Administrator privileges to stop processes...
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b 0
)

echo.
echo Stopping AIPS Backend (Port 8000)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo Stopping AIPS Frontend (Port 5173)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5173') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo [OK] All AIPS background processes have been stopped.
timeout /t 3

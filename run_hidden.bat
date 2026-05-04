@echo off
cd /d "%~dp0"

:: Start backend silently
start /b "" call "%~dp0start_backend.bat" >nul 2>&1

:: Start frontend silently
cd frontend
start /b "" call npm run dev >nul 2>&1

:: Wait for services to bind
timeout /t 4 /nobreak >nul

:: Open browser
start "" "http://localhost:5173"

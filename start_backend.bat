@echo off
echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   AI-IDS NIGHTWATCH  —  Backend Server      ║
echo  ╚══════════════════════════════════════════════╝
echo.
echo  Starting FastAPI server on http://localhost:8000
echo  NOTE: Run as Administrator for live packet capture.
echo.
cd /d "%~dp0backend"
pip install -r requirements.txt -q
uvicorn main:app --reload --port 8000 --host 0.0.0.0

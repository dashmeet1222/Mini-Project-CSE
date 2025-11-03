@echo off
echo Installing ML Intrusion Detection System for Windows
echo ====================================================

echo.
echo Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

echo.
echo Installing Python dependencies...
pip install -r requirements_windows.txt

echo.
echo Checking for Npcap installation...
if exist "C:\Program Files\Npcap\npcap.dll" (
    echo Npcap found - packet capture will work
) else (
    echo WARNING: Npcap not found
    echo For full packet capture functionality, please install Npcap:
    echo https://npcap.com/#download
    echo.
    echo Alternative: The system will work in simulation mode without Npcap
)

echo.
echo Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% == 0 (
    echo Administrator privileges detected - full packet capture available
) else (
    echo WARNING: Not running as Administrator
    echo For real-time packet capture, please run as Administrator
    echo The system will work in simulation mode without admin privileges
)

echo.
echo Installation complete!
echo.
echo To start the system:
echo 1. Run as Administrator: python api_server.py
echo 2. Open web browser to: http://localhost:3000
echo.
pause
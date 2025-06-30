@echo off
REM Enhanced Payment & Credential Scanner - Windows Deployment Script
REM This script automates the deployment process on Windows

setlocal enabledelayedexpansion

echo 🚀 Enhanced Payment ^& Credential Scanner v2.0 - Windows Deployment
echo ====================================================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo ✅ Python found
python --version

REM Check if we're in the right directory
if not exist "enhanced_scanner.py" (
    echo ❌ enhanced_scanner.py not found
    echo Please run this script from the project directory
    pause
    exit /b 1
)

echo ✅ Project files found

REM Create virtual environment
echo 📦 Setting up Python virtual environment...
if not exist "venv" (
    python -m venv venv
    echo ✅ Virtual environment created
) else (
    echo ℹ️ Virtual environment already exists
)

REM Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo 📈 Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo 📥 Installing Python dependencies...
if exist "requirements.txt" (
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
    echo ✅ Dependencies installed successfully
) else (
    echo ❌ requirements.txt not found
    pause
    exit /b 1
)

REM Run installation test
echo 🧪 Running installation tests...
if exist "test_installation.py" (
    python test_installation.py
    if errorlevel 1 (
        echo ❌ Some tests failed
        echo Please check the output above
        pause
        exit /b 1
    )
    echo ✅ All tests passed
) else (
    echo ⚠️ test_installation.py not found, skipping tests
)

REM Create batch file for easy launching
echo 🔗 Creating launch script...
(
echo @echo off
echo cd /d "%%~dp0"
echo call venv\Scripts\activate.bat
echo python enhanced_scanner.py
echo pause
) > launch_scanner.bat

echo ✅ Launch script created: launch_scanner.bat

REM Create directories
echo 📁 Creating directories...
if not exist "data" mkdir data
if not exist "results" mkdir results
if not exist "temp" mkdir temp

REM Check for admin privileges (for network capture)
echo 🔐 Checking administrator privileges...
net session >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Not running as Administrator
    echo Network capture features may require Administrator privileges
    echo Right-click and "Run as Administrator" for full functionality
) else (
    echo ✅ Running as Administrator - network capture available
)

REM Check for WinPcap/Npcap
echo 🌐 Checking network capture capabilities...
if exist "C:\Windows\System32\Packet.dll" (
    echo ✅ WinPcap/Npcap found - network capture available
) else (
    echo ⚠️ WinPcap/Npcap not found
    echo Install Npcap from https://nmap.org/npcap/ for network capture
)

echo.
echo 🎉 Deployment completed successfully!
echo.
echo 📋 Next Steps:
echo   • Double-click launch_scanner.bat to start the application
echo   • Or run: python enhanced_scanner.py
echo   • For network capture: Run as Administrator
echo   • Check QUICK_START.md for usage examples
echo.
echo 🔗 Useful Files:
echo   • launch_scanner.bat - Easy application launcher
echo   • test_installation.py - Test your installation
echo   • QUICK_START.md - Quick start guide
echo   • DEPLOYMENT.md - Full deployment documentation
echo.
echo Happy scanning! 🔍
echo.
pause

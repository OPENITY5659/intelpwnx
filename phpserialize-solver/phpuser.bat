@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   PHPUnser GUI — Portable Launcher
echo ============================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    echo Then run this script again.
    pause
    exit /b 1
)

:: Create venv if missing
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    echo [*] Installing dependencies...
    .venv\Scripts\pip install requests
    echo [*] Setup complete.
)

:: Launch GUI
echo [*] Starting PHPUnser GUI...
.venv\Scripts\python phpuser_gui.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to launch GUI.
    pause
)

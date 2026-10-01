@echo off
title SecureAPI Gateway
color 0A
cd /d "%~dp0"
cls

echo.
echo  ================================================
echo    SecureAPI - Intelligent API Security Gateway
echo  ================================================
echo.
echo  Working folder: %CD%
echo.

REM ========== CHECK PYTHON ==========
python --version >nul 2>&1
if errorlevel 1 goto try_py

echo [OK] Python found
python --version
goto create_venv

:try_py
py --version >nul 2>&1
if errorlevel 1 goto no_python
echo [OK] Python found using py launcher
set PYTHON=py
goto create_venv_py

:no_python
echo.
echo  ================================================
echo   ERROR: Python is NOT installed or not in PATH
echo  ================================================
echo.
echo  Please install Python:
echo    1. Open https://www.python.org/downloads/
echo    2. Download the latest Python 3
echo    3. Run the installer
echo    4. IMPORTANT: Tick the box "Add python.exe to PATH"
echo    5. Click Install Now
echo    6. Restart your computer
echo    7. Run this run.bat again
echo.
echo  Press any key to close this window...
pause >nul
exit /b 1

:create_venv
set PYTHON=python
goto do_venv

:create_venv_py
set PYTHON=py

:do_venv
echo.
echo [1/3] Creating virtual environment (first time only)...
if not exist "venv\Scripts\python.exe" (
    %PYTHON% -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo      Done.
) else (
    echo      Already exists.
)

echo.
echo [2/3] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate venv
    pause
    exit /b 1
)

echo.
echo [3/3] Installing packages (please wait 30-90 seconds)...
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] pip install failed.
    echo Check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo  ================================================
echo   SERVER STARTING...
echo  ================================================
echo.
echo   Open this link in your browser:
echo.
echo      http://127.0.0.1:8000/docs
echo.
echo   Demo accounts:
echo      admin / admin123
echo      alice / alice123
echo      bob   / bob123
echo.
echo   Keep this window open. Press CTRL+C to stop.
echo  ================================================
echo.

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

echo.
echo Server stopped.
pause

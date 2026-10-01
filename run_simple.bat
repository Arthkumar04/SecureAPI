@echo off
title SecureAPI - Manual Mode
cd /d "%~dp0"
cls
echo.
echo This is the SIMPLE version (no virtual environment)
echo.
echo Checking Python...
python --version
if errorlevel 1 (
    echo Python not found. Trying py...
    py --version
    if errorlevel 1 (
        echo.
        echo PYTHON NOT FOUND!
        echo Install from https://www.python.org/downloads/
        echo and tick "Add python.exe to PATH"
        pause
        exit /b 1
    )
    set PY=py
) else (
    set PY=python
)

echo.
echo Installing packages (this may take a minute)...
%PY% -m pip install -r requirements.txt
if errorlevel 1 (
    echo Install failed. Check internet.
    pause
    exit /b 1
)

echo.
echo Starting server...
echo Open: http://127.0.0.1:8000/docs
echo.
%PY% -m uvicorn app.main:app --host 127.0.0.1 --port 8000

pause

@echo off
title Token Info Viewer Service Installer
color 0A
echo ==========================================================
echo     Token Info Viewer (SignBridge Replica) Installer
echo ==========================================================
echo.

:: Paths - Update if needed
set PYTHON_PATH=C:\Users\hp\Downloads\TokenInfo Viewer\TokenInfo Viewer\.venv\Scripts\python.exe
set APP_PATH=C:\Users\hp\Downloads\TokenInfo Viewer\TokenInfo Viewer\app.py
set WORK_DIR=C:\Users\hp\Downloads\TokenInfo Viewer\TokenInfo Viewer
set SERVICE_NAME=TokenInfoViewer
set NSSM_DIR=%~dp0nssm-2.24\win64
set NSSM_EXE=%NSSM_DIR%\nssm.exe

:: Check NSSM exists
if not exist "%NSSM_EXE%" (
    echo ⚠️ NSSM not found!
    echo Please ensure nssm-2.24\win64\nssm.exe exists in the same folder.
    pause
    exit /b
)

:: Install the service
echo 🛠 Installing Windows Service: %SERVICE_NAME%
"%NSSM_EXE%" install %SERVICE_NAME% "%PYTHON_PATH%" "%APP_PATH%"
"%NSSM_EXE%" set %SERVICE_NAME% AppDirectory "%WORK_DIR%"
"%NSSM_EXE%" set %SERVICE_NAME% DisplayName "Token Info Viewer (SignBridge Replica)"
"%NSSM_EXE%" set %SERVICE_NAME% Description "Automatically detects USB tokens (ePass, mToken, ProxKey, SafeNet, etc.)"
"%NSSM_EXE%" set %SERVICE_NAME% AppNoConsole 1
"%NSSM_EXE%" set %SERVICE_NAME% Start SERVICE_AUTO_START

:: Start the service
echo 🚀 Starting the service...
"%NSSM_EXE%" start %SERVICE_NAME%

echo.
echo ✅ Installation Complete!
echo Service Name: %SERVICE_NAME%
echo It will auto-start with Windows.
echo.
pause
exit

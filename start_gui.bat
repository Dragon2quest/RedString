@echo off
title Red String // Web GUI & Control Center
cd /d "%~dp0"

echo ==========================================================================
echo        RED STRING (赤糸) // 1-CLICK WINDOWS GUI LAUNCHER
echo ==========================================================================
echo [*] Initializing Red String Control Deck...

:: Launch browser in background after 1.5s
start "" powershell -NoProfile -Command "Start-Sleep -Milliseconds 1200; Start-Process 'http://localhost:8080'"

:: Start the Python GUI Daemon Server
python red_string_gui_server.py 8080
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Python failed to launch. Checking py launcher...
    py red_string_gui_server.py 8080
)

pause

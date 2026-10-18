@echo off
title Red String // Windows 1-Click Installer
cd /d "%~dp0"

echo ==========================================================================
echo        RED STRING // WINDOWS 1-CLICK INSTALLATION & DESKTOP SETUP
echo ==========================================================================

:: 1. Verify Python
echo [1/2] Checking Python 3 availability...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    py --version >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [!] Python was not found in PATH.
        echo [!] Please install Python 3.9+ from https://www.python.org/
        pause
        exit /b 1
    )
)
echo [+] Python environment detected.

:: 2. Create Desktop Shortcut (.lnk)
echo [2/2] Generating Windows Desktop Shortcut...
set SCRIPT_DIR=%~dp0
set TARGET_BAT=%SCRIPT_DIR%start_gui.bat
set SHORTCUT_PATH=%USERPROFILE%\Desktop\Red String GUI.lnk

powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell; " ^
  "$s = $ws.CreateShortcut('%SHORTCUT_PATH%'); " ^
  "$s.TargetPath = '%TARGET_BAT%'; " ^
  "$s.WorkingDirectory = '%SCRIPT_DIR%'; " ^
  "$s.Description = 'Red String Zero-Trust GUI & Command Deck'; " ^
  "$s.Save()"

echo.
echo ==========================================================================
echo  [SUCCESS] Windows Installation Complete!
echo ==========================================================================
echo  • Created Desktop Shortcut: "%SHORTCUT_PATH%"
echo  • You can now start the GUI at any time by double-clicking:
echo      - The 'Red String GUI' shortcut on your Desktop, OR
echo      - '%TARGET_BAT%'
echo ==========================================================================
echo.
pause

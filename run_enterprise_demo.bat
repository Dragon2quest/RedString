@echo off
echo ========================================================
echo   RED STRING // ENTERPRISE DATATHON PITCH SCRIPT RUNNER
echo ========================================================
echo.
echo Select Demonstration Phase:
echo [1] Phase I: Baseline Sync (Score ^> 0.15, Nominal plain text)
echo [2] Phase II: Threat Ingestion ^& Quarantine (2,500 bursts @ 2ms, high entropy)
echo.
set /p phase="Enter phase (1 or 2): "

cd /d "%~dp0"
python -m enterprise_telemetry.demo_runner --phase %phase%
pause

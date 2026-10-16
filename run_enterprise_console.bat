@echo off
echo ========================================================
echo   RED STRING // ENTERPRISE ZERO-TRUST OPERATIONS CONSOLE
echo   Air-Gapped Telemetry Engine & Edge Intrusion Detection
echo ========================================================
echo.
cd /d "%~dp0"
python -m streamlit run enterprise_telemetry/app.py --server.port 8501 --server.headless false
pause

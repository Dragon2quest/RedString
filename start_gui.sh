#!/usr/bin/env bash
# ==============================================================================
# RED STRING // 1-CLICK WEB GUI & COMMAND CENTER LAUNCHER
# Compatible with Linux (s390x / IBM LinuxONE / x86_64) and Unix Environments
# ==============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT=8080
if [ -n "$1" ]; then
    PORT=$1
fi

echo "=========================================================================="
echo "          RED STRING (赤糸) // ZERO-TRUST WEB GUI CONTROLLER              "
echo "=========================================================================="
echo "[*] Working Directory: $SCRIPT_DIR"
echo "[*] Target Port:       $PORT"

# Ensure Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed or not in PATH."
    echo "[!] Please install Python 3 (e.g. sudo apt install python3 or sudo dnf install python3)."
    exit 1
fi

# Detect IP address
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || LOCAL_IP="127.0.0.1"
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

echo "[*] Local URL:   http://localhost:$PORT"
echo "[*] Network URL: http://$LOCAL_IP:$PORT"
echo "=========================================================================="

# Auto-open browser if running in a desktop graphical environment
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    (
        sleep 1.2
        if command -v xdg-open &> /dev/null; then
            xdg-open "http://localhost:$PORT" >/dev/null 2>&1 || true
        elif command -v gnome-open &> /dev/null; then
            gnome-open "http://localhost:$PORT" >/dev/null 2>&1 || true
        elif command -v python3 &> /dev/null; then
            python3 -m webbrowser "http://localhost:$PORT" >/dev/null 2>&1 || true
        fi
    ) &
fi

# Launch the unified GUI Daemon
exec python3 red_string_gui_server.py "$PORT"

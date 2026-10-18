#!/usr/bin/env bash
# ==============================================================================
# RED STRING // 1-CLICK LINUX INSTALLER & DESKTOP LAUNCHER SETUP
# Supports Ubuntu, Debian, RHEL, Fedora, CentOS, Arch, and IBM LinuxONE (s390x)
# ==============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================================="
echo "          RED STRING // LINUX 1-CLICK INSTALLATION & SETUP                "
echo "=========================================================================="

# 1. Set execution permissions on all scripts
echo "[1/4] Configuring script execution permissions..."
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

# 2. Check Python 3 & ML Libraries
echo "[2/4] Verifying Python runtime and dependencies..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 not detected. Attempting to install..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3 python3-pip
    elif command -v pacman &> /dev/null; then
        sudo pacman -Sy --noconfirm python python-pip
    fi
fi

# Test Python modules
python3 -c "
import sys
missing = []
for mod in ['socket', 'json', 'threading', 'http.server']:
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
if missing:
    print(f'[!] Missing standard modules: {missing}')
    sys.exit(1)
print('[+] Python environment verified.')
"

# 3. Create Desktop Entry & Launcher Icon
echo "[3/4] Creating Desktop application launchers..."
APP_DIR="$HOME/.local/share/applications"
mkdir -p "$APP_DIR"

DESKTOP_FILE="$APP_DIR/red-string-gui.desktop"

cat << EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=Red String GUI
GenericName=Zero-Trust Telemetry Deck
Comment=Enterprise Zero-Trust Fabric & Behavioral ML Quarantine
Exec=$SCRIPT_DIR/start_gui.sh
Path=$SCRIPT_DIR
Terminal=true
Categories=Network;Security;Utility;
StartupNotify=true
EOF

chmod +x "$DESKTOP_FILE"

# Also copy to Desktop if user has a Desktop folder
if [ -d "$HOME/Desktop" ]; then
    cp "$DESKTOP_FILE" "$HOME/Desktop/Red String GUI.desktop"
    chmod +x "$HOME/Desktop/Red String GUI.desktop" 2>/dev/null || true
    echo "[+] Created Desktop shortcut on $HOME/Desktop/Red String GUI.desktop"
fi

# 4. Create optional systemd user service
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
SERVICE_FILE="$SYSTEMD_USER_DIR/red-string-gui.service"

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Red String Zero-Trust Web GUI & Control Center
After=network.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/env python3 $SCRIPT_DIR/red_string_gui_server.py 8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

echo "[4/4] Systemd background service created: $SERVICE_FILE"
echo ""
echo "=========================================================================="
echo " [SUCCESS] Red String Linux Installation Complete!                       "
echo "=========================================================================="
echo " • To launch the GUI with 1 click right now:"
echo "     $SCRIPT_DIR/start_gui.sh"
echo ""
echo " • To launch via application menu or desktop icon:"
echo "     Click 'Red String GUI' on your Desktop or App Launcher"
echo ""
echo " • To enable as an automatic background service (optional):"
echo "     systemctl --user enable --now red-string-gui"
echo "=========================================================================="

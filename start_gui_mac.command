#!/usr/bin/env bash
# ==============================================================================
# RED STRING // 1-CLICK macOS LAUNCHER (Double-Clickable .command file)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

chmod +x start_gui.sh 2>/dev/null || true

# Launch browser after slight delay
(sleep 1.2 && open "http://localhost:8080") &

# Start GUI server
python3 red_string_gui_server.py 8080

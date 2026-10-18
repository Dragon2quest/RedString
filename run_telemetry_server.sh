#!/bin/bash
echo "========================================================"
echo "   RED STRING // ZERO-TRUST AIR-GAPPED TELEMETRY FABRIC"
echo "   Edge Intrusion Detection & Kinetic ML Engine         "
echo "========================================================"
cd "$(dirname "$0")"
python3 -c "
from enterprise_telemetry.server import RedStringServer
import time
srv = RedStringServer(host='0.0.0.0', port=7788)
srv.start()
print('[+] Server active. Press Ctrl+C to terminate.')
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    srv.stop()
    print('\n[*] Server stopped.')
"

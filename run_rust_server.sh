#!/bin/bash
echo "========================================================"
echo "   RED STRING // RUST HIGH-PERFORMANCE DESKTOP SERVER  "
echo "   IBM LinuxONE (s390x) Native Optimized Build          "
echo "========================================================"
cd "$(dirname "$0")/red_string_server"
./target/release/red_string_desktop

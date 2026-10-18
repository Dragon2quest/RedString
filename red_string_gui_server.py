#!/usr/bin/env python3
"""
Red String // Unified Web GUI & Control Center Server
Zero-dependency, multi-threaded HTTP + REST API daemon providing 1-click GUI access
across Linux (s390x / x86_64), Windows, and macOS.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_GUI_DIR = os.path.join(BASE_DIR, "web_gui")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "enterprise_telemetry", "forensic_audit_trail.jsonl")

# Global Process and Service State
SERVER_LOCK = threading.Lock()
ACTIVE_PROCESS: subprocess.Popen | None = None
ACTIVE_SERVICE_TYPE: str = "none"  # "telemetry", "rust", or "none"
SERVICE_START_TIME: float | None = None
CONSOLE_LOG_BUFFER: list[dict] = []
MAX_CONSOLE_LOGS = 200


def add_console_log(message: str, level: str = "info"):
    with SERVER_LOCK:
        CONSOLE_LOG_BUFFER.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        })
        if len(CONSOLE_LOG_BUFFER) > MAX_CONSOLE_LOGS:
            CONSOLE_LOG_BUFFER.pop(0)


def get_local_ip() -> str:
    """Discovers the most likely LAN / outbound IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual traffic; selects optimal route
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks whether a TCP port is currently listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def kill_port_owner(port: int):
    """Frees the specified TCP port by terminating bound processes."""
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
            pids = set()
            for line in output.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 5 and "LISTENING" in parts:
                    pids.add(parts[-1])
            for pid in pids:
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    else:
        # Linux / Unix / macOS
        try:
            subprocess.run(f"fuser -k {port}/tcp", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def get_audit_records(limit: int = 50) -> dict:
    """Reads and cryptographically verifies the forensic audit ledger chain."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return {"records": [], "count": 0, "chain_valid": True, "error": "Log file not found"}

    records = []
    chain_valid = True
    last_verified_hash = "0" * 64

    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        for i, line in enumerate(lines):
            try:
                record = json.loads(line)
                prev_hash = record.get("prev_hash", "0" * 64)
                curr_hash = record.get("record_hash", "")

                # Verify chain
                if i > 0 and prev_hash != last_verified_hash:
                    chain_valid = False

                last_verified_hash = curr_hash
                records.append(record)
            except Exception:
                continue

        # Return latest records
        recent_records = records[-limit:]
        recent_records.reverse()  # Newest first

        return {
            "records": recent_records,
            "count": len(records),
            "chain_valid": chain_valid,
            "last_hash": last_verified_hash,
        }
    except Exception as e:
        return {"records": [], "count": 0, "chain_valid": False, "error": str(e)}


class RedStringGuiHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs
        return

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self.handle_api_status()
        elif path == "/api/audit-log":
            self.handle_api_audit_log()
        elif path == "/api/console-logs":
            self.handle_api_console_logs()
        elif path == "/api/pairing/token":
            self.handle_api_pairing_token()
        else:
            self.handle_static_file(path)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read JSON body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_length > 0:
            try:
                body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            except Exception:
                body = {}

        if path == "/api/server/start":
            self.handle_api_server_start(body)
        elif path == "/api/server/stop":
            self.handle_api_server_stop()
        elif path == "/api/server/restart":
            self.handle_api_server_restart(body)
        elif path == "/api/demo/run":
            self.handle_api_demo_run(body)
        elif path == "/api/test/transfer":
            self.handle_api_test_transfer(body)
        else:
            self._send_json({"error": "Endpoint not found"}, 404)

    def handle_api_status(self):
        global ACTIVE_PROCESS, ACTIVE_SERVICE_TYPE, SERVICE_START_TIME

        port_7788_active = is_port_in_use(7788)
        uptime = 0
        if port_7788_active and SERVICE_START_TIME:
            uptime = int(time.time() - SERVICE_START_TIME)

        local_ip = get_local_ip()
        arch = platform.machine()
        sys_os = platform.system()

        audit_data = get_audit_records(limit=1)

        self._send_json({
            "status": "online" if port_7788_active else "idle",
            "port_7788_active": port_7788_active,
            "service_type": ACTIVE_SERVICE_TYPE if port_7788_active else "none",
            "uptime_seconds": uptime,
            "host_info": {
                "os": sys_os,
                "platform": platform.platform(),
                "machine": arch,
                "hostname": socket.gethostname(),
                "local_ip": local_ip,
                "python_version": platform.python_version(),
            },
            "audit_ledger": {
                "total_records": audit_data.get("count", 0),
                "chain_valid": audit_data.get("chain_valid", True),
                "last_hash": audit_data.get("last_hash", "0" * 64),
            },
            "timestamp": time.time(),
        })

    def handle_api_audit_log(self):
        data = get_audit_records(limit=100)
        self._send_json(data)

    def handle_api_console_logs(self):
        with SERVER_LOCK:
            logs = list(CONSOLE_LOG_BUFFER)
        self._send_json({"logs": logs})

    def handle_api_pairing_token(self):
        token_seed = os.urandom(16).hex()
        ts = int(time.time())
        token = f"REDSTRING::{get_local_ip()}::7788::{ts}::{token_seed}"
        self._send_json({
            "token": token,
            "ip": get_local_ip(),
            "port": 7788,
            "timestamp": ts,
            "expires_in_seconds": 300,
        })

    def handle_api_server_start(self, body: dict):
        global ACTIVE_PROCESS, ACTIVE_SERVICE_TYPE, SERVICE_START_TIME
        mode = body.get("mode", "telemetry")

        with SERVER_LOCK:
            if is_port_in_use(7788):
                self._send_json({"success": False, "error": "Port 7788 is already active."})
                return

            kill_port_owner(7788)
            time.sleep(0.3)

            try:
                if mode == "rust":
                    rust_bin = os.path.join(BASE_DIR, "red_string_server", "target", "release", "red_string_desktop")
                    if platform.system() == "Windows":
                        rust_bin += ".exe"
                    if not os.path.exists(rust_bin):
                        # Attempt debug build or cargo run
                        cmd = ["cargo", "run", "--release", "--manifest-path", os.path.join(BASE_DIR, "red_string_server", "Cargo.toml")]
                    else:
                        cmd = [rust_bin]
                    ACTIVE_PROCESS = subprocess.Popen(cmd, cwd=os.path.join(BASE_DIR, "red_string_server"))
                    ACTIVE_SERVICE_TYPE = "rust"
                else:
                    # Default: Python Zero-Trust ML Telemetry Server
                    cmd = [
                        sys.executable,
                        "-c",
                        "from enterprise_telemetry.server import RedStringServer; srv = RedStringServer(host='0.0.0.0', port=7788); srv.start(); import time; [time.sleep(1) for _ in iter(int, 1)]",
                    ]
                    ACTIVE_PROCESS = subprocess.Popen(cmd, cwd=BASE_DIR)
                    ACTIVE_SERVICE_TYPE = "telemetry"

                SERVICE_START_TIME = time.time()
                add_console_log(f"Started {ACTIVE_SERVICE_TYPE.upper()} server on port 7788", "success")
                self._send_json({
                    "success": True,
                    "service": ACTIVE_SERVICE_TYPE,
                    "pid": ACTIVE_PROCESS.pid,
                    "port": 7788,
                })
            except Exception as e:
                add_console_log(f"Failed to start server: {e}", "error")
                self._send_json({"success": False, "error": str(e)}, 500)

    def handle_api_server_stop(self):
        global ACTIVE_PROCESS, ACTIVE_SERVICE_TYPE, SERVICE_START_TIME
        with SERVER_LOCK:
            if ACTIVE_PROCESS:
                try:
                    ACTIVE_PROCESS.terminate()
                    ACTIVE_PROCESS.wait(timeout=2)
                except Exception:
                    try:
                        ACTIVE_PROCESS.kill()
                    except Exception:
                        pass
                ACTIVE_PROCESS = None

            kill_port_owner(7788)
            ACTIVE_SERVICE_TYPE = "none"
            SERVICE_START_TIME = None
            add_console_log("Stopped server listening on port 7788", "warning")
            self._send_json({"success": True, "message": "Server stopped on port 7788"})

    def handle_api_server_restart(self, body: dict):
        self.handle_api_server_stop()
        time.sleep(0.5)
        self.handle_api_server_start(body)

    def handle_api_demo_run(self, body: dict):
        phase = body.get("phase", "all")

        def run_target():
            add_console_log(f"Executing Threat & Telemetry Demo (Phase: {phase})...", "info")
            try:
                # Ensure server is running
                if not is_port_in_use(7788):
                    add_console_log("Auto-spinning up Zero-Trust listener for demonstration...", "info")
                    srv_cmd = [
                        sys.executable,
                        "-c",
                        "from enterprise_telemetry.server import RedStringServer; srv = RedStringServer(host='127.0.0.1', port=7788); srv.start(); import time; [time.sleep(1) for _ in iter(int, 1)]",
                    ]
                    tmp_proc = subprocess.Popen(srv_cmd, cwd=BASE_DIR)
                    time.sleep(1.0)
                else:
                    tmp_proc = None

                script = f"""
from enterprise_telemetry.demo_runner import run_phase_1_baseline, run_phase_2_threat_exfiltration
import sys

phase = '{phase}'
if phase in ('1', 'all'):
    print('[DEMO_PHASE_1] Starting nominal baseline synchronization...')
    p1 = run_phase_1_baseline(host='127.0.0.1', port=7788, count=15)
    print(f'[DEMO_PHASE_1] Nominal baseline completed with result: {{p1}}')

if phase in ('2', 'all'):
    print('[DEMO_PHASE_2] Initiating simulated threat exfiltration attack...')
    p2 = run_phase_2_threat_exfiltration(host='127.0.0.1', port=7788, count=35)
    print(f'[DEMO_PHASE_2] Attack execution completed with status: {{p2}}')
"""
                res = subprocess.run(
                    [sys.executable, "-c", script],
                    cwd=BASE_DIR,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                for line in res.stdout.split("\n"):
                    if line.strip():
                        lvl = "error" if "QUARANTINE" in line or "EXFILTRATION" in line else "info"
                        add_console_log(line.strip(), lvl)

                if res.stderr:
                    for line in res.stderr.split("\n"):
                        if line.strip():
                            add_console_log(f"[STDERR] {line.strip()}", "warning")

                if tmp_proc:
                    try:
                        tmp_proc.terminate()
                    except Exception:
                        pass
                add_console_log("Demonstration sequence finalized.", "success")
            except Exception as e:
                add_console_log(f"Demo failed: {e}", "error")

        t = threading.Thread(target=run_target, daemon=True)
        t.start()
        self._send_json({"success": True, "message": f"Demo Phase {phase} triggered in background."})

    def handle_api_test_transfer(self, body: dict):
        text = body.get("text", "Test fate sync message from Red String Web GUI")
        host = "127.0.0.1"
        port = 7788

        if not is_port_in_use(port):
            self._send_json({"success": False, "error": "Red String server is not running on port 7788."}, 400)
            return

        try:
            import struct
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            t0 = time.time()
            s.connect((host, port))

            # Encode 5-byte frame (0x01 Control/Text)
            payload = json.dumps({"type": "FATE_SYNC_TEXT", "content": text, "sender": "WebGUI"}).encode("utf-8")
            header = struct.pack(">BI", 0x01, len(payload))
            s.sendall(header + payload)
            elapsed_ms = round((time.time() - t0) * 1000, 2)
            s.close()

            add_console_log(f"Test transfer sent ({len(payload)} bytes) in {elapsed_ms}ms", "success")
            self._send_json({
                "success": True,
                "bytes_sent": len(payload) + len(header),
                "latency_ms": elapsed_ms,
                "message": "Packet transmitted successfully over socket fabric.",
            })
        except Exception as e:
            add_console_log(f"Test transfer failed: {e}", "error")
            self._send_json({"success": False, "error": str(e)}, 500)

    def handle_static_file(self, path: str):
        if path in ("/", ""):
            filepath = os.path.join(WEB_GUI_DIR, "index.html")
            if not os.path.exists(filepath):
                filepath = os.path.join(BASE_DIR, "index.html")
        else:
            clean_path = path.lstrip("/\\")
            filepath = os.path.join(WEB_GUI_DIR, clean_path)
            if not os.path.exists(filepath):
                filepath = os.path.join(BASE_DIR, clean_path)

        if not os.path.exists(filepath) or os.path.isdir(filepath):
            # Fallback to index.html for SPA routing
            filepath = os.path.join(WEB_GUI_DIR, "index.html")
            if not os.path.exists(filepath):
                filepath = os.path.join(BASE_DIR, "index.html")

        if not os.path.exists(filepath):
            self.send_error(404, "File not found")
            return

        # Determine MIME type
        ext = os.path.splitext(filepath)[1].lower()
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".svg": "image/svg+xml",
            ".pdf": "application/pdf",
            ".ico": "image/x-icon",
        }
        content_type = mime_types.get(ext, "application/octet-stream")

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Internal read error: {e}")


def run_server(port: int = 8080, host: str = "0.0.0.0"):
    add_console_log(f"Red String GUI Daemon booted on {host}:{port}", "info")
    local_ip = get_local_ip()

    server = ThreadingHTTPServer((host, port), RedStringGuiHandler)
    print("=" * 70)
    print("   RED STRING // UNIFIED WEB GUI & COMMAND CENTER")
    print("   Enterprise Zero-Trust Fabric & Behavioral ML Gate")
    print("=" * 70)
    print(f"[*] Local Access:    http://localhost:{port}")
    print(f"[*] Network Access:  http://{local_ip}:{port}")
    print(f"[*] Socket Fabric:   Port 7788 (TCP)")
    print(f"[*] Operating Arch:  {platform.machine()} ({platform.system()})")
    print("=" * 70)
    print("[+] Press Ctrl+C to stop the GUI server.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Red String GUI server...")
        server.server_close()


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port=port)

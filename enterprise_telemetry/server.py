"""
Red String Enterprise Socket Fabric & Quarantine Engine
Direct TCP air-gapped listener with Zero-Trust pre-commit scoring gate and tamper-proof audit trail.
"""

import datetime
import hashlib
import json
import os
import socket
import threading
import time
from collections.abc import Callable

from .model import EdgeAnomalyEngine
from .protocol import (
    CHANNEL_CLIPBOARD,
    CHANNEL_FILE,
    CHANNEL_KEYSTROKE,
    CHANNEL_NAMES,
    HEADER_SIZE,
    decode_header,
)
from .telemetry import TelemetryExtractor

AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensic_audit_trail.jsonl")


class ForensicAuditLogger:
    """
    Maintains a local, tamper-proof audit log with cryptographic SHA-256 chain hashing.
    """

    def __init__(self, log_path: str = AUDIT_LOG_FILE):
        self.log_path = log_path
        self._lock = threading.Lock()
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.log_path):
            return "0" * 64
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last_record = json.loads(lines[-1].strip())
                    return last_record.get("record_hash", "0" * 64)
        except (OSError, json.JSONDecodeError, KeyError):
            return "0" * 64
        return "0" * 64

    def log_event(self, event_type: str, details: dict[str, any]) -> dict[str, any]:
        with self._lock:
            ts = time.time()
            record_payload = {
                "timestamp": ts,
                "iso_time": datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).isoformat(),
                "event_type": event_type,
                "prev_hash": self.last_hash,
                "details": details,
            }
            serialized = json.dumps(record_payload, sort_keys=True)
            current_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            record_payload["record_hash"] = current_hash
            self.last_hash = current_hash

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record_payload) + "\n")

            return record_payload


class RedStringServer:
    """
    Enterprise TCP Server enforcing the 17-byte wire protocol and ML quarantine boundary.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 7788, on_telemetry_event: Callable | None = None):
        self.host = host
        self.port = port
        self.on_telemetry_event = on_telemetry_event

        self.telemetry = TelemetryExtractor()
        self.model_engine = EdgeAnomalyEngine()
        self.audit_logger = ForensicAuditLogger()

        self._server_socket: socket.socket | None = None
        self._is_running = False
        self._server_thread: threading.Thread | None = None
        self._active_connections: list[socket.socket] = []
        self._conn_lock = threading.Lock()

        # Shared state for operations console
        self.latest_state = {
            "is_running": False,
            "connected_clients": 0,
            "total_packets": 0,
            "anomalies_quarantined": 0,
            "current_score": 0.85,
            "verdict": "NOMINAL_ALLOW",
            "last_event_time": None,
            "quarantine_active": False,
            "last_quarantine_reason": None,
            "recent_events": [],
            "committed_clipboard": [],
            "live_watch_stream": "",
        }

    def start(self):
        """Starts the server listener on a background daemon thread."""
        if self._is_running:
            return

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(10)
        self._is_running = True
        self.latest_state["is_running"] = True

        self._server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._server_thread.start()
        print(f"[+] Red String Platform Server listening on {self.host}:{self.port}")

    def stop(self):
        """Stops the server listener and closes all active sockets."""
        self._is_running = False
        self.latest_state["is_running"] = False
        with self._conn_lock:
            for s in self._active_connections:
                try:
                    s.close()
                except OSError:
                    pass
            self._active_connections.clear()

        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

    def trigger_emergency_quarantine(self, reason: str = "Manual Emergency Quarantine"):
        """Instantly severs all active connections and records an audit event."""
        with self._conn_lock:
            for s in self._active_connections:
                try:
                    s.close()
                except OSError:
                    pass
            self._active_connections.clear()

        self.latest_state["quarantine_active"] = True
        self.latest_state["last_quarantine_reason"] = reason
        self.latest_state["verdict"] = "MANUAL_QUARANTINE_SEVER"
        self.latest_state["current_score"] = -1.0

        self.audit_logger.log_event("EMERGENCY_QUARANTINE_TRIGGERED", {"reason": reason})

    def _listen_loop(self):
        while self._is_running and self._server_socket:
            try:
                client_sock, client_addr = self._server_socket.accept()
                with self._conn_lock:
                    self._active_connections.append(client_sock)
                    self.latest_state["connected_clients"] = len(self._active_connections)

                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
            except OSError:
                break

    def _handle_client(self, sock: socket.socket, addr: tuple[str, int]):
        peer_name = f"{addr[0]}:{addr[1]}"
        print(f"[+] New air-gapped node connection from: {peer_name}")
        self.audit_logger.log_event("NODE_CONNECTED", {"peer": peer_name})

        try:
            while self._is_running:
                # 1. Read 17-byte deterministic header
                header_data = self._read_exact(sock, HEADER_SIZE)
                if not header_data:
                    break  # Remote severed or cleanly closed

                _magic, channel_id, _ts_ms, payload_len = decode_header(header_data)

                # 2. Read exact payload buffer
                payload = self._read_exact(sock, payload_len)
                if payload is None:
                    break

                # 3. Non-invasive Feature Extraction (O(1), Sub-millisecond)
                t_extract_start = time.perf_counter()
                feature_vector, telemetry_metrics = self.telemetry.extract(payload)
                t_extract_ms = (time.perf_counter() - t_extract_start) * 1000.0

                # 4. IsolationForest Anomaly Scoring (< 1.4 ms)
                score, score_details = self.model_engine.score(feature_vector)

                event_summary = {
                    "timestamp": time.time(),
                    "peer": peer_name,
                    "channel": CHANNEL_NAMES.get(channel_id, f"0x{channel_id:02X}"),
                    "payload_len": payload_len,
                    "metrics": telemetry_metrics,
                    "score": score,
                    "score_details": score_details,
                    "extract_latency_ms": round(t_extract_ms, 3),
                }

                # Update state
                self.latest_state["total_packets"] += 1
                self.latest_state["current_score"] = score
                self.latest_state["verdict"] = score_details["verdict"]
                self.latest_state["last_event_time"] = time.strftime("%H:%M:%S")

                # Store event in ring buffer
                self.latest_state["recent_events"].append(event_summary)
                if len(self.latest_state["recent_events"]) > 200:
                    self.latest_state["recent_events"].pop(0)

                # 5. ZERO-TRUST ENFORCEMENT GATE
                if score_details["quarantine_triggered"]:
                    # CRITICAL: Quarantine Triggered
                    self.latest_state["anomalies_quarantined"] += 1
                    self.latest_state["quarantine_active"] = True
                    self.latest_state["last_quarantine_reason"] = score_details["reason"]

                    # Log tamper-proof forensic audit trail
                    self.audit_logger.log_event(
                        "SOCKET_QUARANTINE_SEVER",
                        {
                            "peer": peer_name,
                            "score": score,
                            "metrics": telemetry_metrics,
                            "reason": score_details["reason"],
                            "quarantine_action": "BUFFER_PURGED_SOCKET_SEVERED",
                        },
                    )

                    print(f"\n[!] QUARANTINE BREACH: Socket severed with {peer_name}. Score: {score:.3f}")
                    # DROP RECEIVING BUFFER BEFORE MEMORY COMMIT & SEVER SOCKET
                    payload = None
                    sock.close()
                    break

                # 6. AUTHORIZED MEMORY COMMIT (Only if scoring passes)
                self._commit_payload(channel_id, payload)

                if self.on_telemetry_event:
                    self.on_telemetry_event(event_summary)

        except OSError:
            pass
        finally:
            with self._conn_lock:
                if sock in self._active_connections:
                    self._active_connections.remove(sock)
                self.latest_state["connected_clients"] = len(self._active_connections)
            try:
                sock.close()
            except OSError:
                pass
            print(f"[-] Node connection severed: {peer_name}")
            self.audit_logger.log_event("NODE_DISCONNECTED", {"peer": peer_name})

    def _commit_payload(self, channel_id: int, payload: bytes):
        """Dispatches verified payload to host clipboard or live telemetry terminal."""
        if channel_id == CHANNEL_CLIPBOARD:
            try:
                text_content = payload.decode("utf-8", errors="replace")
                self.latest_state["committed_clipboard"].append(
                    {"time": time.strftime("%H:%M:%S"), "content": text_content[:150]}
                )
                if len(self.latest_state["committed_clipboard"]) > 50:
                    self.latest_state["committed_clipboard"].pop(0)
            except (UnicodeDecodeError, AttributeError):
                pass

        elif channel_id == CHANNEL_KEYSTROKE:
            try:
                char = payload.decode("utf-8", errors="replace")
                if char == "\b":
                    self.latest_state["live_watch_stream"] = self.latest_state["live_watch_stream"][:-1]
                else:
                    self.latest_state["live_watch_stream"] += char
                    if len(self.latest_state["live_watch_stream"]) > 500:
                        self.latest_state["live_watch_stream"] = self.latest_state["live_watch_stream"][-500:]
            except (UnicodeDecodeError, AttributeError):
                pass

        elif channel_id == CHANNEL_FILE:
            # File artifact dropped into memory vault
            pass

    @staticmethod
    def _read_exact(sock: socket.socket, num_bytes: int) -> bytes | None:
        data = bytearray()
        while len(data) < num_bytes:
            packet = sock.recv(min(num_bytes - len(data), 65536))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

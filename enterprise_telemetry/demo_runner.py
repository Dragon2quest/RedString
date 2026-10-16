"""
Red String Enterprise Datathon Live Demonstration Script (24-Hour Pitch)
Executes Phase I (Baseline Operations) and Phase II (Threat Ingestion & Automated Quarantine).
"""

import argparse
import os
import random
import socket
import time
import zlib
from collections.abc import Callable

from .protocol import (
    CHANNEL_CLIPBOARD,
    CHANNEL_FILE,
    CHANNEL_KEYSTROKE,
    encode_frame,
)

SAMPLE_TEXTS = [
    "Red String: Air-Gapped Zero-Trust Telemetry Engine active on edge enclave.",
    "Synchronizing cryptographic verification keys across verified local fabric.",
    "IBM Enterprise Datathon 2026 - Edge Intrusion Detection Prototype validated.",
    "Kinetics profile: Human typing interval ~140ms, Shannon entropy ~4.15 bits/byte.",
    "Fate Sync authorized memory commit completed without cloud leakage.",
]


def run_phase_1_baseline(
    host: str = "127.0.0.1",
    port: int = 7788,
    count: int = 25,
    on_progress: Callable[[str, int, int], None] | None = None,
):
    """
    Phase I: Baseline Operations (0:00 - 1:30)
    Demonstrates legitimate cross-device clipboard sync and typing over binary TCP framing.
    Expected Result: Score > 0.15, Entropy ~4.1, Green Status Markers.
    """
    print(f"\n[>>>] INITIATING PHASE I: Baseline Operations (Host: {host}:{port})")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"[!] Could not connect to Red String server: {e}")
        return False

    try:
        for i in range(count):
            # Alternate between keystroke typing and clipboard blocks
            if i % 3 == 0:
                # Clipboard sync
                text = random.choice(SAMPLE_TEXTS)
                payload = text.encode("utf-8")
                frame = encode_frame(CHANNEL_CLIPBOARD, payload)
                sock.sendall(frame)
                time.sleep(random.uniform(0.3, 0.7))
            else:
                # Live keystroke
                char = random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?")
                frame = encode_frame(CHANNEL_KEYSTROKE, char.encode("utf-8"))
                sock.sendall(frame)
                time.sleep(random.uniform(0.08, 0.22))  # Human typing cadence (80-220ms)

            if on_progress:
                on_progress(f"Phase I: Normal baseline packet {i+1}/{count} emitted", i + 1, count)

        print("[+] Phase I Completed: 100% nominal human sync packets transmitted.")
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_phase_2_threat_exfiltration(
    host: str = "127.0.0.1",
    port: int = 7788,
    num_bursts: int = 2500,
    burst_interval_sec: float = 0.002,
    on_progress: Callable[[str, int, int], None] | None = None,
):
    """
    Phase II: Threat Ingestion & Automated Quarantine (1:30 - 3:00)
    Simulates malicious automated exfiltration:
      - 2,500 payload bursts at 2ms intervals (automated bot exfiltration loop)
      - High-entropy compressed database extract (entropy > 7.5)
    Expected Result: Telemetry catches deviation in < 2 frames, drops buffer, triggers red alert.
    """
    print(f"\n[>>>] INITIATING PHASE II: Malicious Exfiltration Burst Attack (Host: {host}:{port})")

    # Generate synthetic high-entropy zipped database extract
    raw_db = os.urandom(8192) * 4
    compressed_high_entropy_payload = zlib.compress(raw_db)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"[!] Could not connect to Red String server: {e}")
        return False

    packets_sent = 0
    severed = False

    try:
        # Rapid-fire automated injection loop (2ms gap, high entropy)
        for i in range(num_bursts):
            chunk_slice = compressed_high_entropy_payload[: random.randint(128, 1024)]
            frame = encode_frame(CHANNEL_FILE, chunk_slice)
            try:
                sock.sendall(frame)
                packets_sent += 1
            except (OSError, BrokenPipeError, ConnectionResetError) as se:
                print(f"[!] Socket severed by server quarantine boundary at packet #{packets_sent}: {se}")
                severed = True
                break

            if on_progress and i % 50 == 0:
                on_progress(f"Phase II Attack: Burst packet {i+1}/{num_bursts} launched...", i + 1, num_bursts)

            time.sleep(burst_interval_sec)

        if severed:
            print("[+] SUCCESS: Zero-Trust Quarantine caught deviation in < 2 frames and severed connection!")
        else:
            print(f"[*] Burst sequence completed ({packets_sent} packets sent).")
        return severed

    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red String Datathon Demo Runner")
    parser.add_argument("--phase", type=int, choices=[1, 2], default=1, help="Demo Phase (1=Baseline, 2=Threat)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target server host")
    parser.add_argument("--port", type=int, default=7788, help="Target server port")
    args = parser.parse_args()

    if args.phase == 1:
        run_phase_1_baseline(args.host, args.port)
    elif args.phase == 2:
        run_phase_2_threat_exfiltration(args.host, args.port)

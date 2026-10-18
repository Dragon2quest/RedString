import os
import sys
import time
import socket
import struct
import hashlib
import json

def run_real_pdf_transfer():
    print("=" * 70)
    print("  RED STRING // REAL PDF ARTIFACT WIRE TRANSFER DEMO")
    print("  Direct LAN Binary Chunk Transport (Zero Cloud Transit)")
    print("=" * 70)

    pdf_source = "/home/linux1/red_string/Red_String_Beginners_Guidebook.pdf"
    if not os.path.exists(pdf_source):
        print(f"[!] Source PDF not found at {pdf_source}")
        return

    # 1. Compute Source SHA-256
    with open(pdf_source, "rb") as f:
        file_bytes = f.read()
    total_bytes = len(file_bytes)
    source_sha256 = hashlib.sha256(file_bytes).hexdigest()

    print(f"\n[*] Source Artifact : {os.path.basename(pdf_source)}")
    print(f"    Total Size      : {total_bytes:,} Bytes ({total_bytes/1024:.1f} KB)")
    print(f"    Source SHA-256  : {source_sha256}")

    # 2. Start Receiver Server
    host = "127.0.0.1"
    port = 7795
    received_file_dest = "/home/linux1/red_string/received_Red_String_Beginners_Guidebook.pdf"
    if os.path.exists(received_file_dest):
        os.remove(received_file_dest)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)

    import threading
    received_chunks = []
    server_stats = {"chunks": 0, "bytes": 0}

    def receiver_worker():
        conn, addr = server_sock.accept()
        print(f"\n[+] Red String Socket Established with Peer: {addr[0]}:{addr[1]}")
        with open(received_file_dest, "wb") as f_out:
            while True:
                # Read 17-byte header: !4sBQI
                header = bytearray()
                while len(header) < 17:
                    part = conn.recv(17 - len(header))
                    if not part:
                        break
                    header.extend(part)
                if len(header) < 17:
                    break
                
                magic, channel_id, ts, payload_len = struct.unpack("!4sBQI", header)
                
                # Read payload
                payload = bytearray()
                while len(payload) < payload_len:
                    part = conn.recv(min(payload_len - len(payload), 65536))
                    if not part:
                        break
                    payload.extend(part)
                
                f_out.write(payload)
                f_out.flush()
                server_stats["chunks"] += 1
                server_stats["bytes"] += len(payload)

        conn.close()

    t = threading.Thread(target=receiver_worker, daemon=True)
    t.start()
    time.sleep(0.3)

    # 3. Transmit the PDF through the Red String Wire Client
    print(f"\n[>>>] Slicing PDF into 32 KB frames and transmitting through Red String...")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((host, port))

    chunk_size = 32768  # 32 KB chunks
    chunks_sent = 0
    t_start = time.perf_counter()

    for offset in range(0, total_bytes, chunk_size):
        chunk = file_bytes[offset : offset + chunk_size]
        now_ms = int(time.time() * 1000)
        # 17-byte header: Magic 'RDSG', Channel 0x03 (FILE), Timestamp uint64, Length uint32
        header = struct.pack("!4sBQI", b"RDSG", 0x03, now_ms, len(chunk))
        client_sock.sendall(header + chunk)
        chunks_sent += 1
        time.sleep(0.015)  # 15ms controlled inter-chunk pacing (legitimate file sync cadence)

    client_sock.close()
    t.join(timeout=3.0)
    server_sock.close()
    duration_sec = time.perf_counter() - t_start

    # 4. Verify Integrity & Bit-for-Bit Identity
    print(f"\n[+] Wire Transmission Finished:")
    print(f"    Chunks Emitted  : {chunks_sent}")
    print(f"    Chunks Received : {server_stats['chunks']}")
    print(f"    Bytes Committed : {server_stats['bytes']:,} Bytes")
    print(f"    Throughput Time : {duration_sec:.3f} seconds ({total_bytes / (1024 * duration_sec):.1f} KB/s)")

    if not os.path.exists(received_file_dest):
        print("[!] Error: Received file was not created!")
        return

    with open(received_file_dest, "rb") as f:
        received_bytes = f.read()
    dest_sha256 = hashlib.sha256(received_bytes).hexdigest()

    print(f"\n[*] Cryptographic Integrity Verification:")
    print(f"    Original SHA-256 : {source_sha256}")
    print(f"    Received SHA-256 : {dest_sha256}")

    if source_sha256 == dest_sha256:
        print("\n" + "=" * 70)
        print("  >>> SUCCESS: 100% BIT-FOR-BIT CRYPTOGRAPHIC IDENTITY MATCH! <<<")
        print("  The real PDF traversed the Red String wire protocol flawlessly.")
        print("=" * 70)
    else:
        print("\n[!] Checksum mismatch! Transfer corrupted.")

if __name__ == "__main__":
    run_real_pdf_transfer()

# Red String (赤糸) // Enterprise Zero-Trust Data Fabric & ML Quarantine

[![Architecture](https://img.shields.io/badge/Architecture-IBM%20LinuxONE%20%28s390x%29%20%7C%20x86__64-informational)](https://github.com/Dragon2quest/RedString)
[![Core Engine](https://img.shields.io/badge/Core-Rust%20%2F%20Tokio%20Async-orange)](red_string_server/)
[![Telemetry Gate](https://img.shields.io/badge/ML%20Gate-Python%20%2F%20Isolation%20Forest-blue)](enterprise_telemetry/)
[![Security](https://img.shields.io/badge/Zero--Trust-Autonomous%20Quarantine-red)](enterprise_telemetry/)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Private-lightgrey)](https://github.com/Dragon2quest/RedString)

> **Red String** is an enterprise-grade, air-gapped peer-to-peer data transport fabric coupled with real-time behavioral telemetry and autonomous machine learning quarantine. Designed for dual-enclave operation across edge devices, cross-platform endpoints, and **IBM LinuxONE (s390x)** mainframe infrastructure.

---

## 🏛️ System Architecture

```
                      ┌────────────────────────────────────────┐
                      │          DESKTOP (Rust / Tokio)        │
                      │  • Binds TCP 0.0.0.0:7788              │
                      │  • Enforces Platform Buffer (1GB+15%)  │
                      │  • Emits Magic Circle Pairing Token    │
                      └──────────────────┬─────────────────────┘
                                         │
                         [ Direct LAN / Wi-Fi Socket ]
                                         │
                      ┌──────────────────▼─────────────────────┐
                      │    ENTERPRISE TELEMETRY & ML GATE      │
                      │  • Sub-millisecond Isolation Forest    │
                      │  • O(1) Kinetic Feature Extraction     │
                      │  • Autonomous Socket Severance         │
                      │  • SHA-256 Chained Forensic Ledger     │
                      └──────────────────┬─────────────────────┘
                                         │
                      ┌──────────────────▼─────────────────────┐
                      │          MOBILE / CLIENT INTERFACE     │
                      │  • Magic Circle Visual QR / Token      │
                      │  • Fate Sync & Fate Watch UI           │
                      └────────────────────────────────────────┘
```

The system splits concerns across a **Dual-Enclave Architecture**:
1. **High-Throughput Transport Enclave (`red_string_server`)**: Written in **Rust (Tokio)** for zero-allocation socket streaming, robust memory safety, and 1GB+15% soft/flexible buffer enforcement.
2. **Behavioral Telemetry & ML Scoring Enclave (`enterprise_telemetry`)**: Evaluates transfer patterns in real time using a calibrated **Isolation Forest boundary model**. Suspicious burst dynamics or unverified payload deviations trigger an **instant TCP socket sever and in-memory buffer purge**.

---

## ⚡ Core Features

- **Strict 5-Byte Binary Framing Protocol**:
  - `Byte 0`: Frame Type (`0x01` = JSON Control / Fate Sync, `0x02` = Binary Stream Chunks).
  - `Bytes 1–4`: Payload Length as 32-bit Big-Endian unsigned integer.
  - Zero protocol drift, non-blocking asynchronous parsing.
- **Magic Circle Pairing**:
  - Ephemeral token exchange inspired by esoteric runic knotwork for secure local pairing without external internet dependencies.
- **Sub-Millisecond Edge Anomaly Detection**:
  - Real-time feature extraction measuring kinetic timing, byte-density entropy, and burst distribution.
  - Pre-commit verification before data hits disk or clipboard.
- **Autonomous Zero-Trust Quarantine**:
  - Hard socket closure and volatile buffer zeroization upon anomaly detection.
  - Forensic metadata persisted into a tamper-evident audit ledger.
- **Tamper-Proof SHA-256 Forensic Audit Ledger**:
  - Hash-chained logging (`forensic_audit_trail.jsonl`) ensuring all transfer milestones, baseline flows, and quarantine interventions can be cryptographically verified.
- **Mainframe & Cross-Platform Readiness**:
  - Fully tested and validated on **IBM LinuxONE (s390x enterprise mainframe)** as well as Linux and Windows x86_64 environments.

---

## 📂 Repository Layout

```
RedString/
├── red_string_server/                 # Rust core transport engine
│   ├── Cargo.toml                     # Tokio, serde, byteorder dependencies
│   └── src/
│       ├── main.rs                    # TCP listener, connection handler & platform buffer
│       └── protocol.rs                # 5-byte binary frame encoder/decoder
│
├── enterprise_telemetry/              # Python Zero-Trust ML quarantine service
│   ├── server.py                      # Air-gapped socket listener & quarantine gate
│   ├── model.py                       # Isolation Forest anomaly scoring engine
│   ├── isolation_forest_boundary.joblib # Calibrated edge ML decision boundary
│   ├── telemetry.py                   # O(1) kinetic feature extractor
│   ├── protocol.py                    # Multi-channel framing definitions
│   ├── pairing.py                     # Magic Circle token generation & verification
│   ├── demo_runner.py                 # Live baseline & threat exfiltration demo
│   ├── forensic_audit_trail.jsonl     # SHA-256 hash-chained immutable audit log
│   └── test_suite.py                  # Complete unit and integration test suite
│
├── red_string_gui/                    # Desktop frontend (Tauri / HTML5)
│   ├── src/                           # Runic visualization & pairing interface
│   └── src-tauri/                     # Native desktop bindings
│
├── red_string_mobile/                 # Flutter mobile client workspace
│   └── pubspec.yaml                   # Mobile dependencies & assets
│
├── scripts & execution/
│   ├── run_demo.sh                    # Linux/LinuxONE unified demo script
│   ├── run_rust_server.sh             # Launch Rust transport server
│   ├── run_telemetry_server.sh        # Launch Python telemetry listener
│   ├── run_tests.sh                   # Execute automated test suite
│   ├── transfer_real_pdf.py           # Document transmission verification script
│   ├── run_enterprise_demo.bat        # Windows demonstration launcher
│   └── run_enterprise_console.bat     # Windows console launcher
│
└── documentation & assets/
    ├── Red_String_Beginners_Guidebook.pdf # User & onboarding guidebook
    ├── Red String Enterprise Overhaul Specification.pdf # Enterprise specification
    └── index.html / magic_circle.html # Standalone browser-based visualizers
```

---

### 1. 🖥️ 1-Click Web GUI & Command Center (All Operating Systems)

Red String features an embedded, zero-dependency **Unified Web GUI & Command Center** accessible locally or across the network on port `8080`.

| Operating System | 1-Click Launch Command | Desktop Shortcut Setup |
|:---|:---|:---|
| **🐧 Linux / IBM LinuxONE** | `./start_gui.sh` | `./install_linux.sh` (creates desktop icon & systemd unit) |
| **🪟 Windows (10/11)** | `start_gui.bat` | `install_windows.bat` (creates `.lnk` Desktop shortcut) |
| **🍎 macOS** | `./start_gui_mac.command` | Double-click `start_gui_mac.command` in Finder |

- **Local Access URL**: `http://localhost:8080`
- **Remote Server Access URL**: `http://<server-ip>:8080` (e.g. `http://148.100.108.184:8080`)

#### GUI Capabilities:
- **1-Click Service Management**: Spin up or shut down the Python ML Telemetry listener or Rust high-performance socket fabric on port `7788`.
- **Live Threat & Quarantine Simulator**: Test Phase I (Nominal sync) and Phase II (Simulated attack) with real-time log streaming and sub-millisecond anomaly detection readouts.
- **Magic Circle Pairing Station**: Dynamic rotating canvas glyph generator with 5-minute ephemeral tokens and QR connection strings.
- **Cryptographic Audit Ledger**: Live view of `forensic_audit_trail.jsonl` with automated SHA-256 chain verification badges.
- **Socket Testing Deck**: Transmit custom payloads across the 5-byte framed socket directly from the browser.

---

### 2. Running via Terminal / CLI

#### Prerequisites
- **Rust**: `cargo` and `rustc` (1.70+)
- **Python**: Python 3.9+ with `numpy`, `scikit-learn`, `joblib`
- **Operating System**: Linux (Ubuntu, RHEL, IBM LinuxONE s390x) or Windows 10/11

#### Running on Linux / IBM LinuxONE via CLI:

```bash
# 1. Complete Live Demo (Baseline vs Exfiltration Quarantine)
chmod +x run_demo.sh && ./run_demo.sh

# 2. Run Automated Test Suite
chmod +x run_tests.sh && ./run_tests.sh

# 3. Run Telemetry & Zero-Trust Socket Server
chmod +x run_telemetry_server.sh && ./run_telemetry_server.sh

# 4. Run Native Rust High-Performance Server
chmod +x run_rust_server.sh && ./run_rust_server.sh
```

#### Running on Windows via CLI:
```cmd
run_enterprise_demo.bat
run_enterprise_console.bat
```

---

## 🔒 Binary Protocol Specification

All socket communication uses a strict **5-byte header**:

```
+----------------+-----------------------------------+
| Frame Type (1B)|     Payload Length (4B Big-Endian)|
+----------------+-----------------------------------+
| 0x01 or 0x02   | 0x00 0x00 0x04 0x00               |
+----------------+-----------------------------------+
|                 Payload (N bytes)                  |
+----------------------------------------------------+
```

| Frame Type | Code | Description |
|:---|:---:|:---|
| **Control / Text** | `0x01` | JSON-encoded control packets (`HANDSHAKE_INIT`, `FATE_SYNC_TEXT`, `PAIR_REQUEST`) |
| **Binary Stream** | `0x02` | Raw binary chunks for file transfer and payload exchange |

---

## 🛡️ Security & Quarantine Guarantee

When a client initiates an unauthorized bulk exfiltration or emits anomalous keystroke/network kinetics, the **Edge ML Quarantine Engine** triggers within **< 1ms**:
1. **Socket Sever**: Connection terminated with `SO_LINGER(0)` to instantly drop the TCP session.
2. **Buffer Flush**: Any buffered packets are purged from RAM immediately.
3. **Forensic Record**: A cryptographic block containing the actor IP, time, kinetic delta, and the previous block's SHA-256 hash is sealed into `forensic_audit_trail.jsonl`.

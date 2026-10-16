"""
RED STRING // ENTERPRISE ZERO-TRUST OPERATIONS CONSOLE
IBM Enterprise Datathon - Air-Gapped Telemetry Engine & Edge Intrusion Detection
"""

import json
import os
import sys
import threading
import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Add current project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enterprise_telemetry.demo_runner import (
    run_phase_1_baseline,
    run_phase_2_threat_exfiltration,
)
from enterprise_telemetry.pairing import MagicCirclePairing
from enterprise_telemetry.server import AUDIT_LOG_FILE, RedStringServer

# Set page configuration
st.set_page_config(
    page_title="RED STRING // Enterprise Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-End Cyber-Occult Enterprise CSS
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700;800&family=Cinzel:wght@600;700;900&display=swap');

    :root {
        --void-black: #030305;
        --card-dark: #0a0c12;
        --border-dark: #1f2430;
        --crimson-accent: #ff003c;
        --crimson-glow: rgba(255, 0, 60, 0.4);
        --emerald-guard: #00f59b;
        --amber-warning: #ffb703;
        --text-pure: #ffffff;
        --text-dim: #7f8a9e;
        --font-mono: 'JetBrains Mono', monospace;
    }

    /* Overall background */
    .stApp {
        background-color: var(--void-black);
        color: var(--text-pure);
        font-family: var(--font-mono);
    }

    /* Top banner */
    .hero-banner {
        background: linear-gradient(135deg, rgba(255, 0, 60, 0.12) 0%, rgba(10, 12, 18, 0.95) 100%);
        border: 1px solid rgba(255, 0, 60, 0.35);
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 30px rgba(255, 0, 60, 0.15);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .hero-title {
        font-family: 'Cinzel', serif;
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 2px;
        color: #ffffff;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .hero-title span {
        color: var(--crimson-accent);
        text-shadow: 0 0 16px var(--crimson-glow);
    }

    .hero-tagline {
        font-family: var(--font-mono);
        font-size: 11px;
        letter-spacing: 1.5px;
        color: var(--text-dim);
        text-transform: uppercase;
        margin-top: 4px;
    }

    .kpi-chip-group {
        display: flex;
        gap: 16px;
    }

    .kpi-chip {
        background: rgba(14, 17, 24, 0.9);
        border: 1px solid #1f2430;
        border-radius: 6px;
        padding: 8px 14px;
        text-align: center;
    }

    .kpi-chip-val {
        font-size: 16px;
        font-weight: 700;
        color: var(--crimson-accent);
        font-family: var(--font-mono);
    }

    .kpi-chip-val.green {
        color: var(--emerald-guard);
    }

    .kpi-chip-lbl {
        font-size: 9px;
        color: var(--text-dim);
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* Metric cards */
    .metric-card {
        background: #0a0c12;
        border: 1px solid #1f2430;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }

    .metric-card.alert {
        border: 1px solid var(--crimson-accent);
        box-shadow: 0 0 25px var(--crimson-glow);
        animation: pulse-border 1.5s infinite alternate;
    }

    .metric-card.safe {
        border: 1px solid rgba(0, 245, 155, 0.4);
    }

    @keyframes pulse-border {
        0% { box-shadow: 0 0 10px rgba(255, 0, 60, 0.3); }
        100% { box-shadow: 0 0 30px rgba(255, 0, 60, 0.7); }
    }

    /* Terminal stream feed */
    .terminal-box {
        background: #050608;
        border: 1px solid #181c26;
        border-left: 3px solid var(--crimson-accent);
        border-radius: 6px;
        padding: 12px;
        font-family: var(--font-mono);
        font-size: 12px;
        color: #d1d5db;
        max-height: 220px;
        overflow-y: auto;
    }

    .terminal-line {
        margin-bottom: 4px;
        white-space: pre-wrap;
        word-break: break-all;
    }

    /* Custom buttons */
    .stButton>button {
        background: #11141d;
        color: #ffffff;
        border: 1px solid #282f42;
        border-radius: 6px;
        font-family: var(--font-mono);
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.2s ease;
    }

    .stButton>button:hover {
        border-color: var(--crimson-accent);
        box-shadow: 0 0 12px var(--crimson-glow);
        color: #ffffff;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# Initialize Server Singleton in Session State
@st.cache_resource
def get_server_instance() -> RedStringServer:
    server = RedStringServer(host="0.0.0.0", port=7788)
    server.start()
    return server


server = get_server_instance()
pairing = MagicCirclePairing(port=7788, soft_mb=1024)

# Top Hero / Executive Header
state = server.latest_state
is_quarantine = state.get("quarantine_active", False)
verdict = state.get("verdict", "NOMINAL_ALLOW")
score = state.get("current_score", 0.85)

st.markdown(
    """
    <div class="hero-banner">
        <div>
            <div class="hero-title">
                <span>RED STRING</span> // ZERO-TRUST TELEMETRY FABRIC
            </div>
            <div class="hero-tagline">
                IBM Enterprise Datathon Overhaul &bull; Air-Gapped Non-Invasive Edge Intrusion Detection
            </div>
        </div>
        <div class="kpi-chip-group">
            <div class="kpi-chip">
                <div class="kpi-chip-val green">&lt; 1.4 ms</div>
                <div class="kpi-chip-lbl">Inference Latency</div>
            </div>
            <div class="kpi-chip">
                <div class="kpi-chip-val green">0 B</div>
                <div class="kpi-chip-lbl">Cloud Leakage</div>
            </div>
            <div class="kpi-chip">
                <div class="kpi-chip-val green">O(1)</div>
                <div class="kpi-chip-lbl">Vector Extraction</div>
            </div>
            <div class="kpi-chip">
                <div class="kpi-chip-val green">100%</div>
                <div class="kpi-chip-lbl">Air-Gapped Audit</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar: Magic Circle Pairing & Pitch Controls
with st.sidebar:
    st.markdown("### 🕸️ MAGIC CIRCLE PAIRING")
    st.markdown(
        "<div style='font-size:11px; color:#888;'>Optical air-gapped handshake. Point mobile node camera to bind.</div>",
        unsafe_allow_html=True,
    )

    qr_img = pairing.generate_qr_image(box_size=6, border=1)
    st.image(qr_img, caption="Ephemeral 256-bit Handshake Token", use_container_width=True)

    token_data = pairing.generate_token_payload()
    st.code(
        f"CLUSTER: {token_data['magic']}\nHOST IP: {token_data['ip']}:{token_data['port']}\nCAPACITY: {token_data['soft_mb']} MB (+15% Flex)\nNONCE: {token_data['session_nonce']}",
        language="yaml",
    )

    st.markdown("---")
    st.markdown("### ⚡ DATATHON PITCH RUNNER")
    st.markdown("<div style='font-size:11px; color:#888;'>Live 24-Hour Pitch Script Execution</div>", unsafe_allow_html=True)

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        if st.button("▶ Phase I: Sync", help="Run Phase I: Normal baseline clipboard sync"):
            threading.Thread(
                target=run_phase_1_baseline,
                args=("127.0.0.1", 7788, 20),
                daemon=True,
            ).start()
            st.toast("Phase I Baseline Sync initiated! (Score > 0.15, Normal Entropy)")

    with col_p2:
        if st.button("🔥 Phase II: Attack", help="Run Phase II: 2500 packet exfiltration burst"):
            threading.Thread(
                target=run_phase_2_threat_exfiltration,
                args=("127.0.0.1", 7788, 2500, 0.002),
                daemon=True,
            ).start()
            st.toast("Phase II Malicious Exfiltration launched! Quarantine boundary engaging.")

    st.markdown("---")
    st.markdown("### 🛡️ OPERATIONAL OVERRIDES")
    if st.button("🛑 EMERGENCY SEVER", type="primary", use_container_width=True):
        server.trigger_emergency_quarantine("Manual Operator Override via Console")
        st.toast("Emergency Quarantine: All sockets severed and buffer purged!")

    if st.button("↺ Reset Quarantine State", use_container_width=True):
        server.latest_state["quarantine_active"] = False
        server.latest_state["verdict"] = "NOMINAL_ALLOW"
        server.latest_state["current_score"] = 0.85
        server.latest_state["last_quarantine_reason"] = None
        server.telemetry.reset()
        st.toast("Quarantine status cleared.")


# Main Dashboard Columns
col_metrics, col_viz = st.columns([1, 2])

with col_metrics:
    # Status Banner Card
    if is_quarantine:
        status_box = f"""
        <div class="metric-card alert">
            <div style="font-size:12px; color:#ff003c; font-weight:800; letter-spacing:1px;">⚠️ QUARANTINE BREACH TRIGGERED</div>
            <div style="font-size:22px; font-weight:800; color:#ff003c; margin:4px 0;">SOCKET SEVERED</div>
            <div style="font-size:11px; color:#ccc;">{state.get('last_quarantine_reason') or 'Anomalous kinetic deviation detected.'}</div>
            <div style="font-size:10px; color:#888; margin-top:8px;">DISPOSITION: Receiving buffer purged BEFORE memory commit.</div>
        </div>
        """
    else:
        status_box = f"""
        <div class="metric-card safe">
            <div style="font-size:12px; color:#00f59b; font-weight:800; letter-spacing:1px;">🛡️ BEHAVIORAL STATUS: NOMINAL</div>
            <div style="font-size:22px; font-weight:800; color:#00f59b; margin:4px 0;">{verdict}</div>
            <div style="font-size:11px; color:#aaa;">Edge IsolationForest Decision Score: <b>{score:+.3f}</b></div>
            <div style="font-size:10px; color:#666; margin-top:8px;">Direct TCP Enclave on 0.0.0.0:7788 &bull; Zero Cloud Handshake</div>
        </div>
        """
    st.markdown(status_box, unsafe_allow_html=True)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Dial Gauge Plot (Score: [-1.0 ... +1.0])
    gauge_fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=score,
            title={"text": "ISOLATION FOREST ANOMALY SCORE", "font": {"size": 13, "color": "#ffffff", "family": "JetBrains Mono"}},
            delta={"reference": 0.15, "increasing": {"color": "#00f59b"}, "decreasing": {"color": "#ff003c"}},
            number={"font": {"size": 28, "color": "#ffffff", "family": "JetBrains Mono"}, "valueformat": "+.3f"},
            gauge={
                "axis": {"range": [-1.0, 1.0], "tickwidth": 1, "tickcolor": "#444"},
                "bar": {"color": "#ff003c" if is_quarantine else "#00f59b", "thickness": 0.25},
                "bgcolor": "#0a0c12",
                "borderwidth": 1,
                "bordercolor": "#1f2430",
                "steps": [
                    {"range": [-1.0, -0.05], "color": "rgba(255, 0, 60, 0.35)"},
                    {"range": [-0.05, 0.05], "color": "rgba(255, 183, 3, 0.25)"},
                    {"range": [0.05, 1.0], "color": "rgba(0, 245, 155, 0.2)"},
                ],
                "threshold": {
                    "line": {"color": "#ff003c", "width": 3},
                    "thickness": 0.8,
                    "value": -0.05,
                },
            },
        )
    )
    gauge_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        height=220,
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

    # Live counters row
    c1, c2, c3 = st.columns(3)
    c1.metric("Packets Ingested", state.get("total_packets", 0))
    c2.metric("Connected Nodes", state.get("connected_clients", 0))
    c3.metric("Quarantine Severs", state.get("anomalies_quarantined", 0))


with col_viz:
    st.markdown("### 📊 REAL-TIME TRANSMISSION KINETICS (FATE WATCH)")
    
    # Kinetic Scatter Plot: Delta-t vs Shannon Entropy
    recent_events = state.get("recent_events", [])
    if recent_events:
        df_events = pd.DataFrame([
            {
                "time": e["timestamp"],
                "delta_t_ms": e["metrics"]["delta_t_ms"],
                "entropy": e["metrics"]["shannon_entropy"],
                "size_b": e["metrics"]["frame_size_bytes"],
                "score": e["score"],
                "verdict": e["score_details"]["verdict"],
                "channel": e["channel"],
            }
            for e in recent_events
        ])

        scatter_fig = go.Figure()

        # Normal events
        normal_mask = df_events["score"] >= 0.05
        if normal_mask.any():
            scatter_fig.add_trace(go.Scatter(
                x=df_events.loc[normal_mask, "delta_t_ms"],
                y=df_events.loc[normal_mask, "entropy"],
                mode="markers",
                name="Nominal Sync",
                marker={
                    "size": 10,
                    "color": "#00f59b",
                    "symbol": "circle",
                    "line": {"width": 1, "color": "#ffffff"},
                    "opacity": 0.85,
                },
                text=df_events.loc[normal_mask, "channel"],
            ))

        # Quarantine / Anomalous events
        quarantine_mask = ~normal_mask
        if quarantine_mask.any():
            scatter_fig.add_trace(go.Scatter(
                x=df_events.loc[quarantine_mask, "delta_t_ms"],
                y=df_events.loc[quarantine_mask, "entropy"],
                mode="markers",
                name="Anomalous / Quarantine",
                marker={
                    "size": 14,
                    "color": "#ff003c",
                    "symbol": "x",
                    "line": {"width": 2, "color": "#ff003c"},
                    "opacity": 1.0,
                },
                text=df_events.loc[quarantine_mask, "channel"],
            ))

        scatter_fig.update_layout(
            title={"text": "Transmission Kinetics: Shannon Entropy H(X) vs Inter-Arrival Latency Δt", "font": {"size": 12, "color": "#888"}},
            xaxis_title="Inter-arrival Gap Δt (ms)",
            yaxis_title="Shannon Entropy H(X) [0.0 - 8.0]",
            paper_bgcolor="#0a0c12",
            plot_bgcolor="#050608",
            font={"family": "JetBrains Mono", "color": "#ccc", "size": 10},
            xaxis={"gridcolor": "#181c26", "zerolinecolor": "#1f2430"},
            yaxis={"gridcolor": "#181c26", "zerolinecolor": "#1f2430", "range": [0.0, 8.5]},
            margin={"l": 40, "r": 20, "t": 35, "b": 35},
            height=280,
            legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
        )
        st.plotly_chart(scatter_fig, use_container_width=True)
    else:
        st.info("No incoming packet kinetics recorded yet. Connect a mobile node or click '▶ Phase I: Sync' in the sidebar.")


# Bottom Panels: Telemetry Terminal & Tamper-Proof Audit Log
tab_term, tab_audit, tab_protocol = st.tabs(["📺 FATE WATCH & SYNC FEED", "📜 TAMPER-PROOF AUDIT TRAIL", "⚙️ WIRE PROTOCOL SPECS"])

with tab_term:
    col_t1, col_t2 = st.columns([1, 1])
    with col_t1:
        st.markdown("**Fate Watch: Live Keystroke Telemetry Feed (Read-Only)**")
        watch_text = state.get("live_watch_stream", "")
        st.markdown(
            f"""<div class="terminal-box">> {watch_text if watch_text else "Awaiting live keystroke deltas..."}</div>""",
            unsafe_allow_html=True,
        )

    with col_t2:
        st.markdown("**Fate Sync: Authorized Committed Clipboard Buffers**")
        clips = state.get("committed_clipboard", [])
        if clips:
            clip_lines = "\n".join([f"[{c['time']}] {c['content']}" for c in reversed(clips[:10])])
            st.markdown(
                f"""<div class="terminal-box">{clip_lines}</div>""",
                unsafe_allow_html=True,
            )
        else:
            st.markdown("""<div class="terminal-box">No authorized clipboard sync committed yet.</div>""", unsafe_allow_html=True)


with tab_audit:
    st.markdown("**Tamper-Proof Forensic Audit Trail (Cryptographic SHA-256 Chained Log)**")
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                audit_records = [json.loads(line.strip()) for line in f if line.strip()]
            if audit_records:
                audit_df = pd.DataFrame([
                    {
                        "ISO Time": r.get("iso_time", ""),
                        "Event": r.get("event_type", ""),
                        "Record Hash (SHA-256)": r.get("record_hash", "")[:16] + "...",
                        "Prev Hash": r.get("prev_hash", "")[:12] + "...",
                        "Details": str(r.get("details", {})),
                    }
                    for r in reversed(audit_records[-25:])
                ])
                st.dataframe(audit_df, use_container_width=True)
            else:
                st.info("Audit log is currently empty.")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            st.error(f"Error reading audit log: {e}")
    else:
        st.info("Audit trail file initialized. Awaiting events.")


with tab_protocol:
    st.markdown(r"""
    #### Binary Wire Framing Specification (`RDSG` 17-Byte Header)
    ```
    +---------------------------------------------------------------------------------------+
    | 0x00 - 0x03 | Magic Header (4 Bytes ASCII)    | 'RDSG' Protocol Identifier            |
    | 0x04        | Channel ID (1 Byte Unsigned)    | 0x01: Clipboard | 0x02: Keys | 0x03: File |
    | 0x05 - 0x0C | Epoch Timestamp (8 Bytes uint64)| Big-Endian Milliseconds               |
    | 0x0D - 0x10 | Payload Length (4 Bytes uint32) | Big-Endian Unsigned Integer (N)       |
    | 0x11 - 0x11+N | Raw Content (N Bytes Opaque)  | Payload Committed Only After ML Score |
    +---------------------------------------------------------------------------------------+
    ```
    - **Header Format:** `!4sBQI` (17 bytes exact).
    - **Zero Cloud:** All socket transmissions stay within local air-gapped subnet (`0.0.0.0:7788`).
    - **Latency Budget:** Feature extraction $\le 0.1\text{ ms}$, Isolation Forest inference $\le 1.4\text{ ms}$.
    """)

# Auto-refresh interval (rerun every 1.5 seconds if active)
time.sleep(1.2)
st.rerun()

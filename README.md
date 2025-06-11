# quictelemetry
Real-time QUIC packet analysis, DDoS anomaly detection, and attack simulation using eBPF (BCC), Scapy, and aioquic. Includes tools for logging encrypted QUIC metadata, detecting Initial Flood and Slowloris-style attacks, visualizing CPU usage, and simulating QUIC-layer threats for research and SOC testing.
# 🔐 QUIC Telemetry & Anomaly Detection (eBPF, Scapy, aioquic)

This project enables **real-time telemetry extraction**, **DDoS anomaly detection**, and **attack simulation** on **QUIC (UDP/4433)** traffic using a combination of:

- 🔧 **eBPF with BCC**  
- 🐍 **Scapy** for packet inspection  
- 🌊 **aioquic** for QUIC-based attack generation  
- 📈 **Matplotlib + CSV logging** for analysis and visualization  

It is designed for cybersecurity research, QUIC traffic analysis, and validating defenses against **Initial Flood** and **Slowloris-style** QUIC attacks.

---

## 📂 Included Scripts

| Script | Description |
|--------|-------------|
| `eBPF_quic_monitor.py` | Real-time QUIC metadata collector and anomaly detector using eBPF (BCC). Detects Initial Flood and Loris-style 1-RTT behavior. |
| `scapy_quic.py` | Lightweight Scapy-based logger for all incoming/outgoing QUIC packets. Logs partial connection metadata (DCID, SCID, packet type). |
| `scapy_quic2.py` | Scapy-based anomaly detector for incoming QUIC traffic. Detects Initial Flood attacks using packet heuristics. |
| `atloris.py` | QUIC Slowloris attack simulator. Sends small delayed payloads over multiple long-lived connections to exhaust server resources. |
| `quic_flood.py` | QUIC Flood attack simulator. Rapidly spawns and closes hundreds of connections to overwhelm the target server. |
| `cpuscript.py` | eBPF-based CPU utilization tracker for all processes. Flags high CPU usage caused by attack scripts and plots Python process usage. |

---

## ⚙️ Setup Instructions

### ✅ Requirements

Ensure the following are installed:

- Python 3.8+
- [aioquic](https://github.com/aiortc/aioquic)
- [bcc](https://github.com/iovisor/bcc)
- `scapy`
- `matplotlib`
- `pandas`

### 📦 Install Python Dependencies

```bash
pip install scapy matplotlib pandas aioquic

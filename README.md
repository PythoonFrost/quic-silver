# quictelemetry
Real-time QUIC packet analysis, DDoS anomaly detection, and attack simulation using eBPF (BCC), Scapy, and aioquic. Includes tools for logging encrypted QUIC metadata, detecting Initial Flood and Slowloris-style attacks, visualizing CPU usage, and simulating QUIC-layer threats for research and SOC testing.
# QUIC Telemetry & Anomaly Detection (eBPF, Scapy, aioquic)

This project enables **real-time telemetry extraction**, **DDoS anomaly detection**, and **attack simulation** on **QUIC (UDP/4433)** traffic using a combination of:

- **eBPF with BCC**  
- **Scapy** for packet inspection  
- **aioquic** for QUIC-based attack generation  
- **Matplotlib + CSV logging** for analysis and visualization  

It is designed for cybersecurity research, QUIC traffic analysis, and validating defenses against **Initial Flood** and **Slowloris-style** QUIC attacks.

---

## Included Scripts

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

### Requirements

Ensure the following are installed:

- Python 3.10+
- [aioquic](https://github.com/aiortc/aioquic)
- [bcc](https://github.com/iovisor/bcc)
- `scapy`
- `matplotlib`
- `pandas`

### Install Python Dependencies

```bash
pip install scapy matplotlib pandas aioquic
```
###  For eBPF Scripts (Linux Only)
Install BCC and kernel headers:

```bash
sudo apt update
sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bcc
```

### Usage

## Start Monitoring (eBPF and  Scapy)
``` bash
sudo python3 eBPF_quic_monitor.py
sudo python3 scapy_quic.py
sudo python3 scapy_quic2.py
```

## Start aioquic Server
Before we get started, Generate TLS cert
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```
Then, Run server
```bash
python3 examples/http3_server.py --certificate cert.pem --private-key key.pem
```
or
```bash
python3 examples/http3_server.py --certificate cert.pem --private-key key.pem -l all_log/secret.log -q all_log
```

## Start aioquic Client from another machine
```bash
python3 http3_client.py https://[aioquic server IP]:4433 --insecure
```
## Run QUIC Attack Simulations (aioquic)
#### Loris Attack
```bash
python3 atloris.py
```
#### Flood Attack
```bash
python3 quic_flood.py
```

## Monitor CPU Usage with Visualization
```bash
sudo python3 cpuscript.py
```

After 5 minutes, the script will save:

cpu_utilization_with_python_vis.csv: Raw CPU usage logs

python3_utilization_plot.png: Visual chart showing attack impact on python3 processes

## License

This project is for educational and research purposes.



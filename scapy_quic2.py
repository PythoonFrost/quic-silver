from scapy.all import sniff, UDP, IP
import datetime
import csv
import os
import threading
import time
from collections import defaultdict

OUTPUT_FILE = "quic_telemetry_attack.csv"
ALERT_FILE = "alerts.txt"
QUIC_PORT = 4433

# Detection thresholds against incoming packets to detect DDoS attacks.
INITIAL_PERCENTAGE_THRESHOLD = 70   # 70=70% of Initials among total packets
UNIQUE_SCID_THRESHOLD = 0.8           # 0.7=70% SCIDs should be unique compared to Initials
UNIQUE_DCID_THRESHOLD = 0.8           # 0.7=70% DCIDs should be unique compared to Initials
WINDOW_INTERVAL = 1                   # seconds

# Tracking structures
ip_total_packets = defaultdict(int)
ip_initial_packets = defaultdict(int)
ip_scid_tracker = defaultdict(set)
ip_dcid_tracker = defaultdict(set)

# CSV Headers
if not os.path.exists(OUTPUT_FILE) or os.stat(OUTPUT_FILE).st_size == 0:
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Timestamp', 'Source IP', 'Destination IP',
            'Source Port', 'Dest Port', 'DCID (partial)', 'SCID (partial)',
            'Packet Length', 'Packet Number', 'Packet Type'
        ])

def get_packet_type(first_byte):
    if (first_byte & 0x80) == 0:
        return "Short Header"
    type_bits = (first_byte & 0x30) >> 4
    return {
        0x00: "Initial",
        0x01: "0-RTT",
        0x02: "Handshake",
        0x03: "Retry"
    }.get(type_bits, "Unknown")

def parse_quic_payload(packet):
    global ip_total_packets, ip_initial_packets, ip_scid_tracker, ip_dcid_tracker

    if UDP in packet and packet[UDP].dport == QUIC_PORT:
        try:
            raw_payload = bytes(packet[UDP].payload)
            dcid = "Unknown"
            scid = "Unknown"
            packet_number = "Unknown"
            packet_type = "Unknown"

            if len(raw_payload) < 5:
                return

            first_byte = raw_payload[0]
            header_form = (first_byte & 0x80) >> 7
            packet_type = get_packet_type(first_byte)

            if header_form == 1:  # Long Header
                if len(raw_payload) < 7:
                    return

                version = raw_payload[1:5]
                dcid_len = raw_payload[5]
                dcid_start = 6
                dcid_end = dcid_start + dcid_len

                if dcid_end <= len(raw_payload):
                    dcid = raw_payload[dcid_start:dcid_end].hex()

                if dcid_end >= len(raw_payload):
                    return
                scid_len = raw_payload[dcid_end]
                scid_start = dcid_end + 1
                scid_end = scid_start + scid_len

                if scid_end <= len(raw_payload):
                    scid = raw_payload[scid_start:scid_end].hex()

            else:  # Short Header
                assumed_dcid_len = 8
                dcid_start = 1
                dcid_end = dcid_start + assumed_dcid_len

                if dcid_end <= len(raw_payload):
                    dcid = raw_payload[dcid_start:dcid_end].hex()

            src_ip = packet[IP].src
            ip_total_packets[src_ip] += 1

            if packet_type == "Initial":
                ip_initial_packets[src_ip] += 1
                if scid != "Unknown":
                    ip_scid_tracker[src_ip].add(scid)
                if dcid != "Unknown":
                    ip_dcid_tracker[src_ip].add(dcid)

            # Save to telemetry CSV
            with open(OUTPUT_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    datetime.datetime.now(),
                    packet[IP].src,
                    packet[IP].dst,
                    packet[UDP].sport,
                    packet[UDP].dport,
                    dcid,
                    scid,
                    len(raw_payload),
                    "Unknown",  # Skip packet number for now
                    packet_type
                ])

        except Exception as e:
            print(f"[!] Error parsing packet: {e}")

def log_alert(message):
    with open(ALERT_FILE, "a") as f:
        f.write(message + "\n" + "-"*70 + "\n")
    print(message)
    print("-"*70)

def monitor_behavior():
    global ip_total_packets, ip_initial_packets, ip_scid_tracker, ip_dcid_tracker

    while True:
        time.sleep(WINDOW_INTERVAL)

        for ip in list(ip_total_packets.keys()):
            total = ip_total_packets[ip]
            initials = ip_initial_packets[ip]
            scid_unique = len(ip_scid_tracker[ip])
            dcid_unique = len(ip_dcid_tracker[ip])

            if total == 0:
                continue

            initial_percentage = (initials / total) * 100
            scid_uniqueness = (scid_unique / initials) if initials > 0 else 0
            dcid_uniqueness = (dcid_unique / initials) if initials > 0 else 0

            if (
                initial_percentage >= INITIAL_PERCENTAGE_THRESHOLD and
                scid_uniqueness >= UNIQUE_SCID_THRESHOLD and
                dcid_uniqueness >= UNIQUE_DCID_THRESHOLD
            ):
                alert_message = (
                    f"[ALERT] 🚨 Possible DDoS Attack Detected!\n"
                    f"Source IP: {ip}\n"
                    f"Observation Window: {WINDOW_INTERVAL} second(s)\n"
                    f"Total Packets Seen: {total}\n"
                    f"Initial Packets Seen: {initials}\n"
                    f"Percentage of Initials: {initial_percentage:.2f}%\n"
                    f"Unique SCIDs Observed: {scid_unique}\n"
                    f"Unique DCIDs Observed: {dcid_unique}\n"
                    f"Conclusion: High volume of Initial packets with high SCID/DCID diversity — possible Initial Flood attack.\n"
                    f"Timestamp: {datetime.datetime.now()}"
                )
                log_alert(alert_message)

        # Reset after checking
        ip_total_packets.clear()
        ip_initial_packets.clear()
        ip_scid_tracker.clear()
        ip_dcid_tracker.clear()

# Start sniffing (only incoming QUIC packets)
print(f"[*] Sniffing incoming QUIC packets (UDP dst port {QUIC_PORT})...")
threading.Thread(target=monitor_behavior, daemon=True).start()
sniff(filter=f"udp dst port {QUIC_PORT}", prn=parse_quic_payload, store=False)

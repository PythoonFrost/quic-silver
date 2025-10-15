from scapy.all import sniff, UDP, IP
import datetime
import csv
import os
#This script captures all sort of packets --> incoming/outgoing
OUTPUT_FILE = "quic_telemetry_full.csv"
QUIC_PORT = 4433

# Only write headers if file is new or empty
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
        return "1-RTT"
    type_bits = (first_byte & 0x30) >> 4
    return {
        0x00: "Initial",
        0x01: "0-RTT",
        0x02: "Handshake",
        0x03: "Retry"
    }.get(type_bits, "Unknown")

def parse_quic_payload(packet):
    if UDP in packet and (packet[UDP].dport == QUIC_PORT or packet[UDP].sport == QUIC_PORT):
        try:
            raw_payload = bytes(packet[UDP].payload)
            dcid = "Unknown"
            scid = "Unknown"
            packet_number = "Unknown"
            packet_type = "Unknown"

            if len(raw_payload) < 5:
                return  # Not enough data even for basic header

            first_byte = raw_payload[0]
            header_form = (first_byte & 0x80) >> 7  # 1 = Long Header, 0 = Short Header
            packet_type = get_packet_type(first_byte)

            if header_form == 1:  # Long Header
                if len(raw_payload) < 7:
                    return  # Not enough for Long Header

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

                next_index = scid_end

                if packet_type == "Initial" and next_index < len(raw_payload):
                    token_length = raw_payload[next_index]
                    next_index += 1 + token_length  # Skip token

                if next_index + 2 <= len(raw_payload):
                    packet_number = int.from_bytes(raw_payload[next_index:next_index+2], byteorder='big')
                else:
                    packet_number = "Unknown"

            else:  # Short Header
                assumed_dcid_len = 8
                dcid_start = 1
                dcid_end = dcid_start + assumed_dcid_len

                if dcid_end <= len(raw_payload):
                    dcid = raw_payload[dcid_start:dcid_end].hex()
                else:
                    dcid = "Unknown"

                if dcid_end + 2 <= len(raw_payload):
                    packet_number = int.from_bytes(raw_payload[dcid_end:dcid_end+2], byteorder='big')
                else:
                    packet_number = "Unknown"

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
                    packet_number,
                    packet_type
                ])

        except Exception as e:
            print(f"[!] Error parsing packet: {e}")

# Start sniffing
print(f"[*] Sniffing incoming and outgoing QUIC packets on UDP port {QUIC_PORT}...")
sniff(filter=f"udp port {QUIC_PORT}", prn=parse_quic_payload, store=False)

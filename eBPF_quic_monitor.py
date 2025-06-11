from bcc import BPF
from time import sleep, strftime
import socket
import struct
import csv
import os
from ctypes import Structure, c_uint32, c_uint16, c_uint64, c_uint8
from ctypes import sizeof, string_at
from collections import defaultdict
import time

# Constants
CSV_LOG = "final_quicMeta.csv"
ALERT_FILE = "alerts-ebpf.txt"
INTERFACE = "ens33"  
QUIC_PORT = 4433
ALERT_FLOOD_THRESHOLD = 20  # Preliminary threshold for early detection
CHECK_INTERVAL = 0.5  # Reduced to 0.5 seconds for earlier detection
INITIAL_PERCENTAGE_THRESHOLD = 50  # Reduced to 50% for sensitivity
UNIQUE_SCID_THRESHOLD = 0.8
UNIQUE_DCID_THRESHOLD = 0.8
YOUR_SERVER_IP = "192.168.58.128"  # Replace with your server's IP (e.g., "192.168.58.1")

# eBPF Program
bpf_program = """
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/if_ether.h>
#include <bcc/proto.h>

struct telemetry_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 dcid;
    u64 scid;
    u16 pkt_len;
    u8 pkt_number;
    u8 pkt_type;
};

BPF_PERF_OUTPUT(events);

int monitor_quic(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    struct telemetry_t data = {};
    u32 nh_off = ETH_HLEN;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) return 0;
    if (eth.h_proto != htons(ETH_P_IP)) return 0;
    if (bpf_skb_load_bytes(skb, nh_off, &ip, sizeof(ip)) < 0) return 0;
    if (ip.protocol != 17) return 0; // UDP

    nh_off += ip.ihl * 4;
    if (bpf_skb_load_bytes(skb, nh_off, &udp, sizeof(udp)) < 0) return 0;
    if (udp.dest != htons(4433)) {
        if (udp.source != htons(4433)) {
            return 0;
        }
    } 

    data.src_ip = ip.saddr;
    data.dst_ip = ip.daddr;
    data.src_port = udp.source;
    data.dst_port = udp.dest;
    data.pkt_len = skb->len;

    nh_off += sizeof(udp);

    u8 header[18] = {};
    if (bpf_skb_load_bytes(skb, nh_off, header, sizeof(header)) < 0) return 0;

    data.pkt_type = header[0];
    data.dcid = *((u64 *)&header[1]);
    data.scid = *((u64 *)&header[9]);
    data.pkt_number = header[17];

    events.perf_submit(skb, &data, sizeof(data));
    return 0;
}
"""

# Python Ctypes Structure
class Telemetry(Structure):
    _fields_ = [
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("src_port", c_uint16),
        ("dst_port", c_uint16),
        ("dcid", c_uint64),
        ("scid", c_uint64),
        ("pkt_len", c_uint16),
        ("pkt_number", c_uint8),
        ("pkt_type", c_uint8)
    ]

# Initialize BPF
b = BPF(text=bpf_program)
function = b.load_func("monitor_quic", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function, INTERFACE)

print(f"[+] Monitoring QUIC traffic on {INTERFACE}...")

# Create CSV and ALERT files if not exists
if not os.path.exists(CSV_LOG):
    with open(CSV_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Source_IP", "Destination_IP", "Source_Port", "Destination_Port",
            "DCID", "SCID", "Packet_Length", "Packet_Number", "Packet_Type",
            "Packet_Count", "DCID_Count", "SCID_Count", "Initial_Count", "Anomaly_Flag"
        ])
if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w") as f:
        f.write("")

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

def get_packet_type_name(pkt_type_byte):
    if (pkt_type_byte & 0x80) == 0:
        return "1-RTT Packet"
    type_bits = (pkt_type_byte & 0x30) >> 4
    return {
        0x00: "Initial",
        0x01: "0-RTT",
        0x02: "Handshake",
        0x03: "Retry"
    }.get(type_bits, "Unknown")

def log_alert(message):
    with open(ALERT_FILE, "a") as f:
        f.write(message + "\n" + "-"*70 + "\n")
    print(message)
    print("-"*70)

# State for packet counting
packet_counter = defaultdict(int)
prev_packet_count = defaultdict(int)
dcid_counter_per_src = defaultdict(set)
scid_counter_per_src = defaultdict(set)
initial_counter = defaultdict(int)
short_header_counter = defaultdict(int)  # New counter for 1-RTT Packets
last_window_time = defaultdict(float)
anomaly_state = defaultdict(lambda: "Normal")

def fix_endianess(hexval):
    hex_digits = hexval[2:]  # Remove '0x'
    hex_digits = hex_digits.zfill(16)  # Pad to 16 hex digits
    bytes_val = bytes.fromhex(hex_digits)
    return '0x' + bytes_val[::-1].hex()

def handle_event(cpu, data, size):
    event = Telemetry.from_buffer_copy(string_at(data, sizeof(Telemetry)))
    timestamp = strftime("%Y-%m-%d %H:%M:%S")
    pkt_type_name = get_packet_type_name(event.pkt_type)

    src_ip = ip_to_str(event.src_ip)
    dst_ip = ip_to_str(event.dst_ip)
    src_port = socket.ntohs(event.src_port)
    dst_port = socket.ntohs(event.dst_port)
    dcid_hex = fix_endianess(hex(event.dcid))
    scid_hex = fix_endianess(hex(event.scid))

    # Skip anomaly detection if either src_ip or dst_ip is the server's IP
    if src_ip == YOUR_SERVER_IP:
        anomaly = "Normal"
        # Still log the packet counts for monitoring, but don't flag as anomaly
        packet_counter[src_ip] += 1
        if pkt_type_name == "Initial":
            initial_counter[src_ip] += 1
        elif pkt_type_name == "1-RTT Packet":
            short_header_counter[src_ip] += 1
        dcid_counter_per_src[src_ip].add(dcid_hex)
        scid_counter_per_src[src_ip].add(scid_hex)

        pkt_count = packet_counter[src_ip]
        initial_count = initial_counter[src_ip]
        dcid_count = len(dcid_counter_per_src[src_ip])
        scid_count = len(scid_counter_per_src[src_ip])
        short_header_count = short_header_counter[src_ip]

        current_time = time.time()
        if src_ip not in last_window_time:
            last_window_time[src_ip] = current_time

        if current_time - last_window_time[src_ip] >= CHECK_INTERVAL:
            prev_packet_count[src_ip] = pkt_count
            packet_counter[src_ip] = 0
            initial_counter[src_ip] = 0
            short_header_counter[src_ip] = 0
            dcid_counter_per_src[src_ip].clear()
            scid_counter_per_src[src_ip].clear()
            last_window_time[src_ip] = current_time
    else:
        # Update packet counts for non-server IPs
        packet_counter[src_ip] += 1
        if pkt_type_name == "Initial":
            initial_counter[src_ip] += 1
        elif pkt_type_name == "1-RTT Packet":
            short_header_counter[src_ip] += 1
        dcid_counter_per_src[src_ip].add(dcid_hex)
        scid_counter_per_src[src_ip].add(scid_hex)

        pkt_count = packet_counter[src_ip]
        initial_count = initial_counter[src_ip]
        dcid_count = len(dcid_counter_per_src[src_ip])
        scid_count = len(scid_counter_per_src[src_ip])
        short_header_count = short_header_counter[src_ip]

        current_time = time.time()
        if src_ip not in last_window_time:
            last_window_time[src_ip] = current_time

        anomaly = anomaly_state[src_ip]

        if current_time - last_window_time[src_ip] >= CHECK_INTERVAL:
            if pkt_count > ALERT_FLOOD_THRESHOLD:
                rate_of_change = pkt_count - prev_packet_count[src_ip]
                if rate_of_change > 15:  # Sudden spike threshold
                    anomaly = "Flood"
                    anomaly_state[src_ip] = "Flood"
                    alert_message = (
                        f"[ALERT] 🚨 Possible DDoS Flood Attack Detected!\n"
                        f"Source IP: {src_ip}\n"
                        f"Observation Window: {CHECK_INTERVAL} second(s)\n"
                        f"Total Packets Seen: {pkt_count}\n"
                        f"Packet Rate Increase: {rate_of_change}\n"
                        f"Timestamp: {timestamp}"
                    )
                    log_alert(alert_message)
                elif initial_count > 0:
                    initial_percentage = (initial_count / pkt_count) * 100
                    scid_uniqueness = scid_count / initial_count
                    dcid_uniqueness = dcid_count / initial_count
                    if initial_percentage >= INITIAL_PERCENTAGE_THRESHOLD and scid_uniqueness >= UNIQUE_SCID_THRESHOLD and dcid_uniqueness >= UNIQUE_DCID_THRESHOLD:
                        anomaly = "Flood"
                        anomaly_state[src_ip] = "Flood"
                        alert_message = (
                            f"[ALERT] 🚨 Possible DDoS Attack Detected!\n"
                            f"Source IP: {src_ip}\n"
                            f"Observation Window: {CHECK_INTERVAL} second(s)\n"
                            f"Total Packets Seen: {pkt_count}\n"
                            f"Initial Packets Seen: {initial_count}\n"
                            f"Percentage of Initials: {initial_percentage:.2f}%\n"
                            f"Unique SCIDs Observed: {scid_count}\n"
                            f"Unique DCIDs Observed: {dcid_count}\n"
                            f"Conclusion: High volume of Initial packets with high SCID/DCID diversity — possible Initial Flood attack.\n"
                            f"Timestamp: {timestamp}"
                        )
                        log_alert(alert_message)
                    else:
                        anomaly_state[src_ip] = "Normal"
            else:
                anomaly_state[src_ip] = "Normal"

            # New Loris detection: More than 3 1-RTT Packets
            if short_header_count > 1 and anomaly_state[src_ip] != "Flood":
                anomaly_state[src_ip] = "Loris"
                anomaly = "Loris"
                if short_header_count == 4:  # Log only on first detection in this window
                    alert_message = (
                        f"[ALERT] 🚨 Possible Slowloris Attack Detected!\n"
                        f"Source IP: {src_ip}\n"
                        f"Observation Window: {CHECK_INTERVAL} second(s)\n"
                        f"1-RTT Packet Packets: {short_header_count}\n"
                        f"Timestamp: {timestamp}"
                    )
                    log_alert(alert_message)

            prev_packet_count[src_ip] = pkt_count
            packet_counter[src_ip] = 0
            initial_counter[src_ip] = 0
            short_header_counter[src_ip] = 0
            dcid_counter_per_src[src_ip].clear()
            scid_counter_per_src[src_ip].clear()
            last_window_time[src_ip] = current_time

    # Log the packet details regardless of anomaly status
    with open(CSV_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            dcid_hex,
            scid_hex,
            event.pkt_len,
            event.pkt_number,
            pkt_type_name,
            pkt_count,
            dcid_count,
            scid_count,
            initial_count,
            anomaly
        ])

# Open the buffer
b["events"].open_perf_buffer(handle_event)

# Main loop
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[+] Exiting QUIC Full Metadata Monitor...")
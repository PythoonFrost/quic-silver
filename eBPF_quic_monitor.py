
# eBPF code library
from bcc import BPF

# time keeping and formatting
import time
from time import sleep, strftime

# network socket to attach eBPF program to
import socket

# csv file format to write to
import csv

import os
import struct
from ctypes import Structure, c_uint32, c_uint16, c_uint64, c_uint8
from ctypes import sizeof, string_at
from collections import defaultdict


# Constants
# CVS file (excel sheet) that the QUIC metadata get output to
CSV_LOG = "final_quicMeta.csv"

# alerts file that gets written to
ALERT_FILE = "alerts-ebpf.txt"

# preprogrammed testing env variable
INTERFACE = "ens33"  
QUIC_PORT = 4433

YOUR_SERVER_IP = "192.168.58.128"  # Replace with your server's IP (e.g., "192.168.58.1")

# data to use in monitoring software

# the interval in which the program process the monitored data
CHECK_INTERVAL = 0.5  # Reduced to 0.5 seconds for earlier detection

# number of packets per check interval to trigger a flood alert
ALERT_FLOOD_THRESHOLD = 20  # Preliminary threshold for early detection

# percentage of iniital connection attempt to consider for DDoS
INITIAL_PERCENTAGE_THRESHOLD = 50  # Reduced to 50% for sensitivity
UNIQUE_SCID_THRESHOLD = 0.8
UNIQUE_DCID_THRESHOLD = 0.8

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

# Initialize BPF
# utilising BCC (BPF Compiler Collection) C library to provide the necesseary functions

# creating a BPF object to hold the compiled binary
# compiled from the C code inside the string "bpf_program"
b = BPF(text=bpf_program)

# load the BPF program into the kernel (load_funct)
# a "SOCKET_FILTER" type program executes whenever a packet arrives at the socket it is attached to
# the function "monitor_quic" will be the program being executed
function = b.load_func("monitor_quic", BPF.SOCKET_FILTER)

# attaches the loaded eBPF program to the raw socket on the network interface
# since all packets passing through the interface must go through the raw socket
# meaning all packets must be passed on through the "monitor_quic" function
BPF.attach_raw_socket(function, INTERFACE)

# output to command line
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

# Python Ctypes Structure
# hold telemetry data on the QUIC packet (header and pkt stuff)
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

# convert ip to string
def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

# return the name of a packet
# packet type data is stored in one byte
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

# write a new line with the message to the alert text file
def log_alert(message):
    with open(ALERT_FILE, "a") as f:
        f.write(message + "\n" + "-"*70 + "\n")
    print(message)
    print("-"*70)

# State for packet counting
# hash map containing the number of packets from a source IP address
packet_counter = defaultdict(int)

# hash map containing
prev_packet_count = defaultdict(int)

# hash map containing a set of unique dcid and scid per source IP address
dcid_counter_per_src = defaultdict(set)
scid_counter_per_src = defaultdict(set)

# int values counting the number of 0-RTT and 1-RTT packets per source IP address
initial_counter = defaultdict(int)
short_header_counter = defaultdict(int)  # New counter for 1-RTT Packets

# hash map containing the time of the last packet from the source IP address 
last_window_time = defaultdict(float)

# hash map of anomaly states (default "Normal")
anomaly_state = defaultdict(lambda: "Normal")


# change the Endian orientation (big vs small endian) of the hex value
def fix_endianess(hexval):
    hex_digits = hexval[2:]  # Remove '0x'
    hex_digits = hex_digits.zfill(16)  # Pad to 16 hex digits
    bytes_val = bytes.fromhex(hex_digits)
    return '0x' + bytes_val[::-1].hex()


# event handler
def handle_event(cpu, data, size):
    
    # copy the telemetry data from the ring buffer
    # alongside the packet type and timestamp (formatted using strftime)
    event = Telemetry.from_buffer_copy(string_at(data, sizeof(Telemetry)))
    timestamp = strftime("%Y-%m-%d %H:%M:%S")
    pkt_type_name = get_packet_type_name(event.pkt_type)
    
    # set values according to the telemetry data
    # ip to str convert IP address to String
    src_ip = ip_to_str(event.src_ip)
    dst_ip = ip_to_str(event.dst_ip)
    
    # The ntohl() function converts the unsigned integer netlong from network byte order to host byte order
    # QUINN: wtf are these redundant a-- data structure!?!?!
    src_port = socket.ntohs(event.src_port)
    dst_port = socket.ntohs(event.dst_port)
    
    # get the dcid hex in the correct format (big endian) using custom function
    dcid_hex = fix_endianess(hex(event.dcid))
    scid_hex = fix_endianess(hex(event.scid))

    # Skip anomaly detection if either src_ip or dst_ip is the server's IP
    if src_ip == YOUR_SERVER_IP:
        
        # Still log the packet counts for monitoring, but don't flag as anomaly
        anomaly = "Normal"
        
        # increment the packet counter for the source IP address
        packet_counter[src_ip] += 1
        
        # check to see if packet is the initial handshake or 1 RTT
        # increment the equivalent counter if yes
        # QUINN: we could pass on packet type byte itself for the if statement
        if pkt_type_name == "Initial":
            initial_counter[src_ip] += 1
        elif pkt_type_name == "1-RTT Packet":
            short_header_counter[src_ip] += 1
        
        # Add each unique source and destination ID to their respective 
        dcid_counter_per_src[src_ip].add(dcid_hex)
        scid_counter_per_src[src_ip].add(scid_hex)

        # get the total number of packets sent from source IP
        # and the number of initial handshakes / 1RTT
        pkt_count = packet_counter[src_ip]
        initial_count = initial_counter[src_ip]
        short_header_count = short_header_counter[src_ip]
        
        # get the number of unique source and destination id
        dcid_count = len(dcid_counter_per_src[src_ip])
        scid_count = len(scid_counter_per_src[src_ip])
        
        # get current time
        current_time = time.time()


        # check to see if there was a packet sent from source ip before
        # if set the time the last packet was sent to the current time
        if src_ip not in last_window_time:
            last_window_time[src_ip] = current_time
        
        # when the time between two packets 
        # is larger than the processing interval
        # if yes clear the data 
        # and set the number of prev packets for the last interval to be the number of packet recorded

        # QUINN: Does seems like a good way to save on performace when the number of packets to be processed is low
        
        if current_time - last_window_time[src_ip] >= CHECK_INTERVAL:
            
            # set no. prev packet for the last interval
            prev_packet_count[src_ip] = pkt_count
            
            # clear all data
            packet_counter[src_ip] = 0
            initial_counter[src_ip] = 0
            short_header_counter[src_ip] = 0
            dcid_counter_per_src[src_ip].clear()
            scid_counter_per_src[src_ip].clear()
            
            # set the last time that the packet was sent from the source IP
            # to the current system time
            last_window_time[src_ip] = current_time
            
           
    else:
        # Update packet counts for non-server IPs
        packet_counter[src_ip] += 1
        
        # increment the counter of the corresponding packet type
        if pkt_type_name == "Initial":
            initial_counter[src_ip] += 1
        elif pkt_type_name == "1-RTT Packet":
            short_header_counter[src_ip] += 1
        
        # same set of procedure as above
        # QUINN: could we eliminate duplicate code and improve readability by putting it outside the if statement?
        dcid_counter_per_src[src_ip].add(dcid_hex)
        scid_counter_per_src[src_ip].add(scid_hex)

        pkt_count = packet_counter[src_ip]
        initial_count = initial_counter[src_ip]
        short_header_count = short_header_counter[src_ip]
        
        dcid_count = len(dcid_counter_per_src[src_ip])
        scid_count = len(scid_counter_per_src[src_ip])

        current_time = time.time()
        
        # same as above, set the time the last packet was detected to the current time
        if src_ip not in last_window_time:
            last_window_time[src_ip] = current_time
        
        # get the anomaly state of the current source IP
        # the anomaly state is "Normal" by default
        anomaly = anomaly_state[src_ip]

        # check if interval between two packets is longer than the checking interval
        if current_time - last_window_time[src_ip] >= CHECK_INTERVAL:
            
            # check if the number of packets from the source IP is over the threshold (hardcoded)
            if pkt_count > ALERT_FLOOD_THRESHOLD:
                
                # rate of change is the difference in number of packets (from the source IP) 
                # between the two intervals
                rate_of_change = pkt_count - prev_packet_count[src_ip]
                
                # if rate of change is high (hardcoded value again), log a flood alert
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
                
                # else if there are a low spike and there are more than one initial packet
                elif initial_count > 0:
                    
                    # count the percentage of initial packets out of all packets
                    initial_percentage = (initial_count / pkt_count) * 100
                    
                    # count the unique source/destination IDs per initial packets
                    scid_uniqueness = scid_count / initial_count
                    dcid_uniqueness = dcid_count / initial_count
                    
                    # if there are a high number of initial packets coming in and the ids remain highly distinct
                    # many new machine are making a new connection to the server
                    # log a possible DDoS attack
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
                    
                    # else don't raise alerts
                    else:
                        anomaly_state[src_ip] = "Normal"
            # same as above
            # QUINN: duplicate code, first else can be deleted
            else:
                anomaly_state[src_ip] = "Normal"
            
            
            # New Loris detection: More than 3 1-RTT Packets 
            # if there are more than one (hardcoded) 1-RTT and alert state is Flood
            # change alert to Loris
            if short_header_count > 1 and anomaly_state[src_ip] != "Flood":
                anomaly_state[src_ip] = "Loris"
                anomaly = "Loris"
                
                # more than 3 short/broken header forcing server to do a connection routine
                if short_header_count == 4:  # Log only on first detection in this window
                    alert_message = (
                        f"[ALERT] 🚨 Possible Slowloris Attack Detected!\n"
                        f"Source IP: {src_ip}\n"
                        f"Observation Window: {CHECK_INTERVAL} second(s)\n"
                        f"1-RTT Packet Packets: {short_header_count}\n"
                        f"Timestamp: {timestamp}"
                    )
                    log_alert(alert_message)

            # set the previous packet count to be the current one
            prev_packet_count[src_ip] = pkt_count
            
            # set the last window time to be current time
            last_window_time[src_ip] = current_time
            
            # clear all data
            packet_counter[src_ip] = 0
            initial_counter[src_ip] = 0
            short_header_counter[src_ip] = 0
            dcid_counter_per_src[src_ip].clear()
            scid_counter_per_src[src_ip].clear()

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

# we tell BCC to open the perf buffer reader on the BPF_PERF_BUFFER called "events"
# whenever an event happen (write to buffer) we invoke the event handler "handle _event" with the event payload

# our BPF code write to buffer using this code:
# events.perf_submit(skb, &data, sizeof(data));
# with data being a telemetry_t struct

b["events"].open_perf_buffer(handle_event)

# Main loop
try:
    # loop is always true
    while True:
        # wait for events in an open perf buffer - "events" which we open up earlier
        # pull event out of kernel and dispactch to python callback (handle_event in our case)
        b.perf_buffer_poll()
        
# Press any key to interrupt program        
except KeyboardInterrupt:
    print("\n[+] Exiting QUIC Full Metadata Monitor...")

#!/usr/bin/env python3
from bcc import BPF
from ctypes import Structure, c_uint32, c_uint64
import socket
import sys
import time
import threading
import argparse
import os
import signal

# get the eBPF program source file 
BPF_SOURCE_FILE = "eBPF.c"

#define the structure for the eBPF program's output
class Summary(Structure):
    _fields_ = [
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("pkt_count", c_uint64),
        ("conn_count", c_uint64),
        ("malformed_count", c_uint64),
        ("handshake_count", c_uint64),
    ]

#helper functions

#convert the ip to a string
def ip_to_str(ip):
    return socket.inet_ntoa(ip.to_bytes(4, "little"))

#format the summary to be displayed as f-strings
def format_summary(event, iface):
    return (
        f"[{iface}] {ip_to_str(event.src_ip)} → {ip_to_str(event.dst_ip)} | "
        f"pkts={event.pkt_count:<6} conn={event.conn_count:<4} "
        f"handshake={event.handshake_count:<3} malformed={event.malformed_count:<3}"
    )

#event handler for the ring buffer
def handle_event(cpu, data, size, iface):
    event = Summary.from_buffer_copy(data)
    print(format_summary(event, iface))

#Per-interface worker
#this allow for monitoring of multiple interfaces

class InterfaceWorker(threading.Thread):
    def __init__(self, iface):
        super().__init__(daemon=True)
        self.iface = iface
        self.bpf = None
        self.running = True

    def run(self):
        print(f"[*] Attaching eBPF program to interface: {self.iface}")

        # Load eBPF program
        with open(BPF_SOURCE_FILE, "r") as f:
            src = f.read()

        self.bpf = BPF(text=src)

        # Load and attach eBPF function
        fn = self.bpf.load_func("monitor_quic", BPF.SCHED_CLS)

        # Attach to interface ingress
        self.bpf.attach_tc(
            dev=self.iface,
            fn_name="monitor_quic",
            replace=True,
            attach_point="ingress",
        )

        # Open ring buffer and register callback
        rb = self.bpf["events"]
        rb.open_ring_buffer(lambda cpu, data, size: handle_event(cpu, data, size, self.iface))

        try:
            while self.running:
                self.bpf.ring_buffer_poll(100)
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

    def cleanup(self):
        if not self.running:
            return
        self.running = False
        print(f"[x] Detaching eBPF program from {self.iface}")
        try:
            self.bpf.remove_tc(dev=self.iface, attach_point="ingress")
        except Exception as e:
            print(f"Warning: could not detach from {self.iface}: {e}")

def main():
    
    #we are using argparse to parse command line options
    parser = argparse.ArgumentParser(
        description="eBPF-based QUIC telemetry collector"
    )
    
    #arguments that can be added for the program
    parser.add_argument(
        "-i",
        "--interface",
        nargs="+",
        required=True,
        help="Network interfaces to attach (e.g. eth0 eth1 wlan0)",
    )
    
    args = parser.parse_args()

    #list of workers
    workers = []

    #graceful exit handler
    def exit_handler(sig, frame):
        print("\n[!] Stopping all workers...")
        for w in workers:
            w.cleanup()
        sys.exit(0)
    
    #signal.signal() allow for "defining custom handlers to be executed when a signal is received"
    #SIGINT is the Interrupt from keyboard (CTRL + C)
    #signal.SIGTERM is the Termination signal
    #calls the exit handler when either signal is recieved
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    #launch a worker per interface listed
    for iface in args.interfaces:
        w = InterfaceWorker(iface)
        w.start()
        workers.append(w)


    print(f"[*] Running collector for eBPF-based QUIC telemetry. Press Ctrl + C to stop...")

    #keep main thread alive
    #optional sleep() is included to keep program from consuming too many CPU while running
    while True:
        time.sleep(5) #optional

if __name__ == "__main__":
    main()

import pyshark
import csv
from datetime import datetime, timedelta
import signal
import sys
from collections import defaultdict

# Define supported protocols
PROTOCOLS = {"TCP"}

# Sliding window parameters
WINDOW_SIZE = timedelta(seconds=10)  # 10-second window
MAX_VERTICAL_SCAN_THRESHOLD = 5  # Number of unique ports per IP
MAX_HORIZONTAL_SCAN_THRESHOLD = 5  # Number of unique IPs per port


def capture_packets(interface='lo',
                    scanner_ip='127.0.0.1',
                    output_file='packet_dataset.csv'):
    """
    Capture TCP traffic, log each response packet with individual flags, duration, and scan types.
    Each response packet is logged in a separate row.
    """

    bpf_filter = (
        f"host {scanner_ip} and tcp"
    )

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    print(f"[*] Starting packet capture on {interface} with filter: {bpf_filter}")
    print(f"    Output CSV: {output_file}")

    # Write CSV headers if the file is new
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "start_time",
            "end_time",
            "duration",
            "src_ip", "dst_ip",
            "src_port", "dst_port",
            "SYN", "ACK", "FIN", "RST", "URG", "PSH",
            "vertical_scan", "horizontal_scan" , "label"
        ])

    start_time = None
    previous_timestamp = None
    window_packets = []
    vertical_scans = defaultdict(set)  # src_ip -> set of dst_ports
    horizontal_scans = defaultdict(set)  # dst_port -> set of src_ips

    def signal_handler(sig, frame):
        print("[*] Capture stopped by user.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start sniffing
    with open(output_file, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        for packet in capture.sniff_continuously():
            if 'ip' not in packet:
                continue

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            timestamp = packet.sniff_time
            protocol = packet.highest_layer

            if start_time is None:
                start_time = timestamp

            if protocol not in PROTOCOLS:
                continue

            src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else None
            dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else None

            # TCP Flags
            tcp_flags = int(packet.tcp.flags, 16)
            syn = 1 if (tcp_flags & 0x02) else 0
            ack = 1 if (tcp_flags & 0x10) else 0
            fin = 1 if (tcp_flags & 0x01) else 0
            rst = 1 if (tcp_flags & 0x04) else 0
            urg = 1 if (tcp_flags & 0x20) else 0
            psh = 1 if (tcp_flags & 0x08) else 0

            # Filter response packets (ACK flag set without SYN or FIN)
            is_response = ack == 1 and syn == 0 and fin == 0
            if not is_response:
                continue

            # Duration Calculation
            duration = 0
            if previous_timestamp:
                duration = (timestamp - previous_timestamp).total_seconds()
            previous_timestamp = timestamp

            # Add packet to sliding window
            window_packets.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port
            })

            # Remove expired packets from the window
            window_packets = [p for p in window_packets if timestamp - p['timestamp'] <= WINDOW_SIZE]

            # Update scan tracking structures
            vertical_scans[src_ip].add(dst_port)
            horizontal_scans[dst_port].add(src_ip)

            # Detect scans
            vertical_scan = 1 if len(vertical_scans[src_ip]) > MAX_VERTICAL_SCAN_THRESHOLD else 0
            horizontal_scan = 1 if len(horizontal_scans[dst_port]) > MAX_HORIZONTAL_SCAN_THRESHOLD else 0

            # Write to CSV
            writer.writerow([
                start_time,
                timestamp,
                duration,
                src_ip, dst_ip,
                src_port, dst_port,
                syn, ack, fin, rst, urg, psh,
                vertical_scan, horizontal_scan , 0
            ])

    print(f"[+] Capture complete. Data saved to {output_file}")


if __name__ == "__main__":
    capture_packets(
        interface='br-92ee71a2a290',
        scanner_ip='172.31.0.2',
        output_file='datasets/second/good.csv'
    )

"""
To run in Docker:

# Create Network
docker network create \
  --driver bridge \
  --subnet=172.31.0.0/24 \
  custom_bridge

# Start Container
docker run -dit --name traffic_generator \
  --network custom_bridge \
  --ip 172.31.0.2 \
  -v .:/tmp/temp \
  ubuntu:22.04 bash

# From Container:
nmap -sT 172.31.0.1 -p 0-5000 # TCP Scan
nmap -sS 172.31.0.1 -p 0-5000 # Stealth Scan
nmap -sF 172.31.0.1 -p 0-5000 # FIN Scan
nmap -sN 172.31.0.1 -p 0-5000 # NULL Scan
nmap -sX 172.31.0.1 -p 0-5000 # XMAS Scan
"""

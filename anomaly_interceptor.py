import pyshark
import csv
from datetime import datetime, timedelta
import signal
import sys
from collections import defaultdict
import threading
import time

# Sliding window parameters
WINDOW_SIZE = timedelta(seconds=0.5)  # 0.5-second window
SAVE_INTERVAL = 1  # Save sessions every 1 second

def capture_packets(interface='lo',
                    scanner_ip='127.0.0.1',
                    output_file='packet_dataset.csv',
                    label=1
                    ):
    """
    Capture TCP traffic, aggregate request/response packet data, and log them in CSV.
    """
    bpf_filter = f"host {scanner_ip} and tcp"
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    print(f"[*] Starting packet capture on {interface} with filter: {bpf_filter}")
    print(f"    Output CSV: {output_file}")

    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "start_request_time",
            "end_request_time",
            "start_response_time",
            "end_response_time",
            "duration",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "SYN", "ACK", "FIN", "RST", "URG", "PSH",
            "label"
        ])

    sessions = defaultdict(lambda: {
        'start_request_time': None,
        'end_request_time': None,
        'start_response_time': None,
        'end_response_time': None,
        'duration': 0,
        'src_ips': set(),
        'dst_ips': set(),
        'src_ports': set(),
        'dst_ports': set(),
        'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'URG': 0, 'PSH': 0,
        'last_updated': datetime.now()
    })

    def save_sessions_periodically():
        while True:
            current_time = datetime.now()
            with open(output_file, mode='a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                for session_key, ss in list(sessions.items()):
                    if (current_time - ss['last_updated']) > WINDOW_SIZE or len(sessions[session_key]) > 1:
                        writer.writerow([
                            ss['start_request_time'],
                            ss['end_request_time'],
                            ss['start_response_time'],
                            ss['end_response_time'],
                            ss['end_response_time'] - ss['start_request_time'], # duration
                            list(ss['src_ips']),
                            list(ss['dst_ips']),
                            list(ss['src_ports']),
                            list(ss['dst_ports']),
                            ss['SYN'],
                            ss['ACK'],
                            ss['FIN'],
                            ss['RST'],
                            ss['URG'],
                            ss['PSH'],
                            label # label
                        ])
                        del sessions[session_key]
            time.sleep(SAVE_INTERVAL)

    saver_thread = threading.Thread(target=save_sessions_periodically, daemon=True)
    saver_thread.start()

    def signal_handler(sig, frame):
        print("[*] Capture stopped by user.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    with open(output_file, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        for packet in capture.sniff_continuously():
            if 'ip' not in packet or 'tcp' not in packet:
                continue

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            timestamp = packet.sniff_time
            tcp_flags = int(packet.tcp.flags, 16)

            syn = 1 if (tcp_flags & 0x02) else 0
            ack = 1 if (tcp_flags & 0x10) else 0
            fin = 1 if (tcp_flags & 0x01) else 0
            rst = 1 if (tcp_flags & 0x04) else 0
            urg = 1 if (tcp_flags & 0x20) else 0
            psh = 1 if (tcp_flags & 0x08) else 0

            session_key = tuple(sorted([src_ip, dst_ip, src_port, dst_port])) # use as session key a tuple of information

            if syn == 1:  # Request packet
                if sessions[session_key]['start_request_time'] is None:
                    sessions[session_key]['start_request_time'] = timestamp
                sessions[session_key]['end_request_time'] = timestamp
            elif ack == 1:  # Response packet
                if sessions[session_key]['start_response_time'] is None:
                    sessions[session_key]['start_response_time'] = timestamp
                sessions[session_key]['end_response_time'] = timestamp

            sessions[session_key]['src_ips'].update([src_ip, dst_ip])
            sessions[session_key]['dst_ips'].update([dst_ip, src_ip])
            sessions[session_key]['src_ports'].update([src_port, dst_port])
            sessions[session_key]['dst_ports'].update([dst_port, src_port])

            sessions[session_key]['SYN'] += syn
            sessions[session_key]['ACK'] += ack
            sessions[session_key]['FIN'] += fin
            sessions[session_key]['RST'] += rst
            sessions[session_key]['URG'] += urg
            sessions[session_key]['PSH'] += psh

            sessions[session_key]['last_updated'] = datetime.now()

    print(f"[+] Capture complete. Data saved to {output_file}")


if __name__ == "__main__":
    capture_packets(
        interface='br-92ee71a2a290',
        scanner_ip='172.31.0.2',
        output_file='datasets/third/bad.csv',
        label=1
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

import pyshark
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time

# Sliding window parameters
WINDOW_SIZE = timedelta(seconds=0.5)  # Session timeout window
SAVE_INTERVAL = 1  # Save in the csv every second

# TCP FLAG PATTERNS
REQUEST_PATTERNS = {
    "TCP_REQUEST": lambda f: f['SYN'] == 1 and f['ACK'] == 0,
    "STEALTH_SCAN": lambda f: f['SYN'] == 1 and f['RST'] == 1,
    "FIN_SCAN": lambda f: f['FIN'] == 1 and f['ACK'] == 0,
    "PSH_SCAN": lambda f: f['PSH'] == 1 and f['ACK'] == 0,
    "URG_SCAN": lambda f: f['URG'] == 1 and f['ACK'] == 0,
    "XMAS_SCAN": lambda f: f['FIN'] == 1 and f['PSH'] == 1 and f['URG'] == 1,
    "NULL_SCAN": lambda f: all(v == 0 for v in f.values())
}

RESPONSE_PATTERNS = {
    "TCP_RESPONSE": lambda f: f['ACK'] == 1 and f['SYN'] == 0,
    "RST_RESPONSE": lambda f: f['RST'] == 1
}

def capture_packets(interface='lo',
                    scanner_ip='127.0.0.1',
                    output_file='packet_dataset.csv',
                    label=None):
    """
    Capture TCP traffic, aggregate request/response packet data, and log them in CSV.
    """
    bpf_filter = f"host {scanner_ip} and tcp"
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    print(f"[*] Starting packet capture on {interface} with filter: {bpf_filter}")
    print(f"[*] Output CSV: {output_file}")

    # Initialize CSV
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        header = [
            "start_request_time", "end_request_time",
            "start_response_time", "end_response_time",
            "duration", "src_ip", "dst_ip",
            "src_port", "dst_port",
            "SYN", "ACK", "FIN", "RST", "URG", "PSH"
        ]
        
        if label is not None:
            header.append("label")
            
        writer.writerow(header)

    sessions = defaultdict(lambda: {
        'start_request_time': None,
        'end_request_time': None,
        'start_response_time': None,
        'end_response_time': None,
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
                    # Each seconds we try to save a session raw if WINDOW_SIZE time is elapsed
                    if (current_time - ss['last_updated']) > WINDOW_SIZE:
                        end_time = ss['end_response_time'] or ss['end_request_time']
                        if ss['end_response_time'] is None:
                            ss['start_response_time'] = 0
                            ss['end_response_time'] = 0

                        row = [
                            ss['start_request_time'], ss['end_request_time'],
                            ss['start_response_time'], ss['end_response_time'],
                            (end_time - ss['start_request_time']).total_seconds() if end_time else 0.0,
                            list(ss['src_ips']), list(ss['dst_ips']),
                            list(ss['src_ports']), list(ss['dst_ports']),
                            ss['SYN'], ss['ACK'], ss['FIN'], ss['RST'], ss['URG'], ss['PSH'],
                        ]

                        if label is not None:
                            row.append(label)
                        
                        writer.writerow(row)
                        
                        del sessions[session_key]
            time.sleep(SAVE_INTERVAL)

    # Use a separate thread for managing csv 
    saver_thread = threading.Thread(target=save_sessions_periodically, daemon=True)
    saver_thread.start()

    # get_tcp_flags
    # uses & operator just for getting the correct flag position within the entire packet structure
    # if it is present 1 is returned for such flag otherwise not present, 0
    def get_tcp_flags(packet):
        return {
            'SYN': 1 if (int(packet.tcp.flags, 16) & 0x02) else 0,
            'ACK': 1 if (int(packet.tcp.flags, 16) & 0x10) else 0,
            'FIN': 1 if (int(packet.tcp.flags, 16) & 0x01) else 0,
            'RST': 1 if (int(packet.tcp.flags, 16) & 0x04) else 0,
            'URG': 1 if (int(packet.tcp.flags, 16) & 0x20) else 0,
            'PSH': 1 if (int(packet.tcp.flags, 16) & 0x08) else 0
        }

    for packet in capture.sniff_continuously():
        if 'ip' not in packet or 'tcp' not in packet:
            continue

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport
        timestamp = packet.sniff_time

        tcp_flags = get_tcp_flags(packet)
        
        # Adjust session_key for FIN, NULL, XMAS scans
        if any(pattern(tcp_flags) for pattern in [
            REQUEST_PATTERNS['FIN_SCAN'],
            REQUEST_PATTERNS['NULL_SCAN'],
            REQUEST_PATTERNS['XMAS_SCAN']
        ]):
            session_key = tuple(sorted([src_ip, dst_ip])) # chnage session key since these scan could not contain a response
        else:
            session_key = tuple(sorted([src_ip, dst_ip, src_port, dst_port]))

        # Detect Request Patterns
        if any(pattern(tcp_flags) for pattern in REQUEST_PATTERNS.values()):
            if sessions[session_key]['start_request_time'] is None:
                sessions[session_key]['start_request_time'] = timestamp
            sessions[session_key]['end_request_time'] = timestamp

        # Detect Response Patterns
        if any(pattern(tcp_flags) for pattern in RESPONSE_PATTERNS.values()):
            if sessions[session_key]['start_response_time'] is None:
                sessions[session_key]['start_response_time'] = timestamp
            sessions[session_key]['end_response_time'] = timestamp

        # Update IPs and Ports
        sessions[session_key]['src_ips'].add(src_ip)
        sessions[session_key]['dst_ips'].add(dst_ip)
        sessions[session_key]['src_ports'].add(src_port)
        sessions[session_key]['dst_ports'].add(dst_port)

        # Increment TCP Flags
        sessions[session_key]['SYN'] += tcp_flags['SYN']
        sessions[session_key]['ACK'] += tcp_flags['ACK']
        sessions[session_key]['FIN'] += tcp_flags['FIN']
        sessions[session_key]['RST'] += tcp_flags['RST']
        sessions[session_key]['URG'] += tcp_flags['URG']
        sessions[session_key]['PSH'] += tcp_flags['PSH']

        # Update Last Updated Time
        sessions[session_key]['last_updated'] = datetime.now()

"""
    To generete traffic through docker container
    IF YOU USED COMPOSE TO BUILD THE CONTAINER YOU CAN SKIP THIS

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
    
    # Delayed scan (second datasets)    
    nmap -p 1-10000 --scan-delay 1s 172.31.0.1

    RUN from main for creating train datasets assigning labels 0 and 1 based on the traffic type
"""
if __name__ == "__main__":
    output_file = 'datasets/delayed/good.csv'
    capture_packets(
        interface='br-442842f5362e', # Change it based on your interface name, to grab it, do an ifconfig from terminal
        scanner_ip='172.31.0.2', # change it based on ipv4_address from docker compose file
        output_file=output_file,
        label=0 # change label accordingly
    )
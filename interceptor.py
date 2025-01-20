import pyshark
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time
import asyncio 

# Sliding window parameters
WINDOW_SIZE = timedelta(seconds=0.5)  # Session timeout window
SAVE_INTERVAL = 1  # Save in the csv every second

# TCP FLAG PATTERNS
REQUEST_PATTERNS = {
    "TCP_SCAN": lambda f: (f['SYN'] == 1) or (f['ACK'] == 1) or (f['RST'] == 1 and f['ACK'] == 1),
    
    "STEALTH_SCAN": lambda f: (f['SYN'] == 1) or (f['RST'] == 1),
    
    "FIN_SCAN": lambda f: f['FIN'] == 1,

    "NULL_SCAN": lambda f: all(v == 0 for v in f.values()),
    
    "XMAS_SCAN": lambda f: f['FIN'] == 1 and f['PSH'] == 1 and f['URG'] == 1
}

RESPONSE_PATTERNS = {
    "TCP_RESPONSE": lambda f: (f['SYN'] == 1 and f['ACK'] == 1) or (f['RST'] == 1 and f['ACK'] == 1),
    
    "STEALTH_RESPONSE": lambda f: (f['SYN'] == 1 and f['ACK'] == 1) or (f['RST'] == 1 and f['ACK'] == 1), # same as normal tcp, easy
    
    "FIN_RESPONSE": lambda f: all(v == 0 for v in f.values()) or (f['RST'] == 1 and f['ACK'] == 1),
     
    "NULL_RESPONSE": lambda f: all(v == 0 for v in f.values()) or (f['RST'] == 1 and f['ACK'] == 1),
    
    "XMAS_RESPONSE": lambda f: all(v == 0 for v in f.values()) or (f['RST'] == 1 and f['ACK'] == 1)
}

def capture_packets(interface='lo',
                    scanner_ip='127.0.0.1',
                    output_file='packet_dataset.csv',
                    label=None,
                    stop_event=threading.Event()):
    """
    Capture TCP traffic, aggregate request/response packet data, and log them in CSV.
    """
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


    def save_sessions_periodically(stop_event=threading.Event()):
        while not stop_event.is_set():
            current_time = datetime.now()
            with open(output_file, mode='a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                for session_key, ss in list(sessions.items()):
                        
                    # Each seconds we try to save a session raw if WINDOW_SIZE time is elapsed
                    if (current_time - ss['last_updated']) > WINDOW_SIZE:
                        
                        end_time = ss['end_response_time'] or ss['end_request_time'] # give priority to end_response_time
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
    saver_thread = threading.Thread(target=save_sessions_periodically, args=(stop_event,), daemon=True)
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

    loop = asyncio.new_event_loop() # for windows operating system 
    asyncio.set_event_loop(loop)
    
    bpf_filter = f"host {scanner_ip} and tcp"
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    print(f"[*] Starting packet capture on {interface} with filter: {bpf_filter}")
    print(f"[*] Output CSV: {output_file}")
    
    try:
        for packet in capture.sniff_continuously():
            if 'ip' not in packet or 'tcp' not in packet:
                continue
            
            if stop_event.is_set():
                return
        
            src_ip = packet.ip.src  
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            timestamp = packet.sniff_time
            
            tcp_flags = get_tcp_flags(packet)
            
            # Detect Request Patterns
            # Check direction: is it from the scanner (request) or from the target (response)? 
            # Adjust session_key for FIN, NULL, XMAS scans
            if any(pattern(tcp_flags) for pattern in [
                REQUEST_PATTERNS['FIN_SCAN'],
                REQUEST_PATTERNS['NULL_SCAN'],
                REQUEST_PATTERNS['XMAS_SCAN']
            ]):
                session_key = tuple([src_port, dst_port])
                reversed_session_key = session_key # set reversed_session_key since these scan could not contain a response, dst_port is the only one not changing
            else:
                session_key = tuple([src_port, dst_port])
                reversed_session_key = tuple([dst_port, src_port])  
            
            is_request = True # assume it is a request
            
            if reversed_session_key in sessions:
                # If the reversed session_key exists, consider it not a request but a response
                session_key = reversed_session_key  # Use the reversed session_key for further updates
                is_request = False
                
            # print(src_port)
            # Update request timings
            if is_request:
                
                #print("REQUEST" + str(tcp_flags))
                if any(pattern(tcp_flags) for pattern in REQUEST_PATTERNS.values()):
                    if sessions[session_key]['start_request_time'] is None:
                        sessions[session_key]['start_request_time'] = timestamp
                    sessions[session_key]['end_request_time'] = timestamp
            else:
                
                #print("RESPONSE" + str(tcp_flags))
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
    finally:
        asyncio.set_event_loop(None)
        loop.close()

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
    nmap -sT 172.31.0.1 -p 0-2500 # TCP Scan
    nmap -sS 172.31.0.1 -p 0-2500 # Stealth Scan
    nmap -sF 172.31.0.1 -p 0-2500 # FIN Scan
    nmap -sN 172.31.0.1 -p 0-2500 # NULL Scan
    nmap -sX 172.31.0.1 -p 0-2500 # XMAS Scan
    
    # Delayed scan (second datasets)    
    nmap -p 1-5000 --scan-delay 1s 172.31.0.1

    RUN from main for creating train datasets assigning labels 0 and 1 based on the traffic type
"""
if __name__ == "__main__":
    output_file = 'datasets/train/bad.csv'
    capture_packets(
        interface='br-442842f5362e', # Change it based on your interface name, to grab it, do an ifconfig from terminal
        scanner_ip='172.31.0.2', # change it based on ipv4_address from docker compose file
        output_file=output_file,
        label=1 # change label accordingly
    )
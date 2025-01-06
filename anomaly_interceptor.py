import pyshark
import csv
from collections import defaultdict
from datetime import datetime
import signal
import sys

# Define supported protocols
PROTOCOLS = {"TCP"}

def create_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """
    Create a canonical 5-tuple key to identify a flow bidirectionally.
    Sort IPs (and ports if the same IP) so that reversed pairs map to the same key.
    """
    # A simple approach: if src_ip < dst_ip, keep as (src_ip, dst_ip, src_port, dst_port).
    # If src_ip > dst_ip, flip them. If src_ip == dst_ip, compare ports.
    if src_ip < dst_ip:
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    elif src_ip > dst_ip:
        return (dst_ip, src_ip, dst_port, src_port, protocol)
    else:
        # IPs are the same, so compare ports
        if src_port <= dst_port:
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)


def capture_flows(interface='lo',
                  scanner_ip='127.0.0.1',
                  output_file='flows_scan.csv'):
    """
    Capture TCP, UDP, and ICMP traffic, group them into bidirectional flows,
    and label anomalies (simple example label=1).
    No time-based window is used for grouping; direction-agnostic 5-tuple identifies the flow.
    """

    bpf_filter = (
        f"host {scanner_ip} and ("
        f"(tcp and (tcp[13] & 0x12 == 0x02)) or "   # SYN Scan
        f"(tcp and (tcp[13] & 0x10 == 0x10)) or "   # ACK Scan
        f"(tcp and (tcp[13] & 0x01 == 0x01)) or "   # FIN Scan
        f"(tcp and (tcp[13] == 0x00)) or "          # NULL Scan
        f"(tcp and (tcp[13] & 0x29 == 0x29)) "   # XMAS Scan
        ")"
    )

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    # Flow storage: each entry is keyed by a 5-tuple ignoring direction
    flows = defaultdict(lambda: {
        "timestamp_start": None,
        "timestamp_end": None,
        "src_ports": set(),
        "dst_ports": set(),
        "tcp_flags_pattern": [],
        "packet_count": 0
    })

    label = 0  # Just an example “malicious” label

    print(f"[*] Starting capture on {interface} with filter: {bpf_filter}")
    print(f"    Output CSV: {output_file}")

    # Write CSV headers if the file is new
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "timestamp_start", "timestamp_end", "flow_key",    # 5-tuple (or a representation)
            "src_ports", "dst_ports", "packet_count",
            "tcp_flags_pattern", "label"
        ])

    def signal_handler(sig, frame):
        """Handle Ctrl+C: write out flows and exit."""
        print("[*] Capture stopped by user.")
        write_flows_to_csv(flows, output_file, label)
        sys.exit(0)

    # Register the signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Start sniffing
    for packet in capture.sniff_continuously():
        if 'ip' not in packet:
            continue

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        timestamp = packet.sniff_time
        protocol = packet.highest_layer  # e.g., TCP, UDP, ICMP

        if protocol not in PROTOCOLS:
            continue

        # For TCP and UDP, we have ports
        src_port = None
        dst_port = None

        if protocol == "TCP" and hasattr(packet, 'tcp'):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

        # Build direction-agnostic key
        flow_key = create_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        flow = flows[flow_key]

        # Update flow timestamps
        if flow["timestamp_start"] is None:
            flow["timestamp_start"] = timestamp
        flow["timestamp_end"] = timestamp
        flow["packet_count"] += 1

        # TCP Handling
        if protocol == "TCP":
            tcp_flags = int(packet.tcp.flags, 16)
            syn = 1 if (tcp_flags & 0x02) else 0
            ack = 1 if (tcp_flags & 0x10) else 0
            fin = 1 if (tcp_flags & 0x01) else 0
            rst = 1 if (tcp_flags & 0x04) else 0
            urg = 1 if (tcp_flags & 0x20) else 0
            psh = 1 if (tcp_flags & 0x08) else 0
            flow["tcp_flags_pattern"].append((syn, ack, fin, rst, urg, psh))
            flow["src_ports"].add(packet.tcp.srcport)
            flow["dst_ports"].add(packet.tcp.dstport)


    # Once capture ends (for example, container stops, or script ends):
    write_flows_to_csv(flows, output_file, label)
    print(f"[+] Capture complete. Data saved to {output_file}")


def write_flows_to_csv(flows, output_file, label):
    """Write out all flows to CSV."""
    with open(output_file, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        for flow_key, flow_data in flows.items():
            # flow_key is something like (src_ip, dst_ip, src_port, dst_port, protocol)
            writer.writerow([
                flow_data["timestamp_start"],
                flow_data["timestamp_end"],
                flow_key,
                list(flow_data["src_ports"]),
                list(flow_data["dst_ports"]),
                flow_data["packet_count"],
                flow_data["tcp_flags_pattern"],
                label
            ])


if __name__ == "__main__":
    capture_flows(
        interface='br-92ee71a2a290',
        scanner_ip='172.31.0.2',
        output_file='packets_scan_good.csv',
    )

"""
docker network create \
  --driver bridge \
  --subnet=172.31.0.0/24 \
  custom_bridge

docker run -dit --name traffic_generator \
  --network custom_bridge \
  --ip 172.31.0.2 \
  -v .:/tmp/temp \
  ubuntu:22.04 bash
  
from container:

nmap -sT 172.31.0.1 -p 0-5000 # TCP SCAN
nmap -sS 172.31.0.1 -p 0-5000 # Stealth Scan
nmap -sF 172.31.0.1 -p 0-5000 # Fin scan
nmap -sN 172.31.0.1 -p 0-5000 # Null scan
nmap -sN 172.31.0.1 -p 0-5000 # Xmas scan

"""
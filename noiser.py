#!/usr/bin/env python3

import requests
import time

TARGET_HOST = "172.31.0.1"  # Replace with the actual target IP/hostname
NUM_RANDOM_PORTS = 12000     # Number of random ports to try each cycle
SLEEP_SECONDS = 0        # Time to wait between cycles

def generate_noise(target_host=TARGET_HOST,num_random_ports=NUM_RANDOM_PORTS,sleep_seconds=SLEEP_SECONDS):
    """
    Send HTTP GET requests to random ports and one known open port (OPEN_PORT).
    """
    # 1) Make requests to random ports
    for port in range(1,num_random_ports):
        #port = random.randint(1, 65535)  # choose a random port in [1..65535]
        url = f"http://{target_host}:{port}/"
        print(f"Trying {url}")
        try:
            # Using a short timeout to avoid blocking for too long on closed or filtered ports
            requests.get(url, timeout=10)
            print(f"[Random Port] Sent request to {url}")
        except Exception as e:
             # We expect many of these to fail if the port is closed or filtered
            pass

        # 3) Sleep briefly before sending next batch of requests
        time.sleep(sleep_seconds)

if __name__ == "__main__":
    try:
        generate_noise()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

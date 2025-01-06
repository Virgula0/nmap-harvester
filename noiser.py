#!/usr/bin/env python3

import requests
import random
import time

TARGET_HOST = "172.31.0.1"  # Replace with the actual target IP/hostname
NUM_RANDOM_PORTS = 6000     # Number of random ports to try each cycle
SLEEP_SECONDS = 1         # Time to wait between cycles

def generate_noise():
    """
    Send HTTP GET requests to random ports and one known open port (OPEN_PORT).
    """
    # 1) Make requests to random ports
    for port in range(NUM_RANDOM_PORTS):
        #port = random.randint(1, 65535)  # choose a random port in [1..65535]
        url = f"http://{TARGET_HOST}:{port}/"
        print(f"Trying {url}")
        try:
                # Using a short timeout to avoid blocking for too long on closed or filtered ports
            requests.get(url, timeout=0.5)
            print(f"[Random Port] Sent request to {url}")
        except Exception as e:
             # We expect many of these to fail if the port is closed or filtered
            pass

        # 3) Sleep briefly before sending next batch of requests
        time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    try:
        generate_noise()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

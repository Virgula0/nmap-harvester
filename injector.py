import time
import random
import nmap
import requests as r
from utils import save_logs

SLEEP_TIME = 1
PROBABILITY_INJECTION = 10 # 10% of probabilities to inject an anomaly each SLEEP_TIME seconds
nm = nmap.PortScanner()

def should_inject() -> bool:
    """
    Determines if an injection should happen based on PROBABILITY_INJECTION.
    """
    random_number = random.uniform(0, 100)
    return random_number < PROBABILITY_INJECTION

def choose_random_port():
    return random.randint(1, 65_535)

def run_nmap(IP_ADDRESS):
    nm.scan(IP_ADDRESS, '0-50')

def run_injector(IP_ADDRESS='127.0.0.1'):
    while True:
        message = ""
        if should_inject():
            message = "[INJECTOR] Running NMAP on first 50 ports"
            run_nmap(IP_ADDRESS)
        else:
            # normal traffic
            PORT = choose_random_port()
            url = f"http://{IP_ADDRESS}:{PORT}/"
            message = f"[INJECTOR] Normal traffic request on {url}"
            try:
                r.get(url, timeout=1)
            except Exception as ex:
                pass # ignore if port is closed
        
        print(message)
        save_logs((message + "\n",))

        time.sleep(SLEEP_TIME)
        continue
        
    
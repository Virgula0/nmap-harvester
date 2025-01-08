import time
import random
import nmap
import requests as r

SLEEP_TIME = 1
SLEEP_TIME_ON_INJECT = 10
PROBABILITY_INJECTION = 10 # 10% of probbailities to inject an anomaly
nm = nmap.PortScanner()

def should_inject() -> bool:
    """
    Determines if an injection should happen based on PROBABILITY_INJECTION.

    Args:
        PROBABILITY_INJECTION (int): PROBABILITY_INJECTION percentage (0-100).

    Returns:
        bool: True if the random number matches the probability condition, False otherwise.
    """
    random_number = random.uniform(0, 100)
    return random_number < PROBABILITY_INJECTION

def choose_random_port():
    return random.randint(1, 65_535)

def run_nmap(IP_ADDRESS):
    nm.scan(IP_ADDRESS, '0-50')

def run_injector(IP_ADDRESS='localhost'):
    
    while True:
        if should_inject():
            print("[INJECTOR] Running NMAP on first 50 ports")
            run_nmap(IP_ADDRESS)
        else:
            # normal traffic
            PORT = choose_random_port()
            url = f"http://{IP_ADDRESS}:{PORT}/"
            print(f"[INJECTOR] Normal traffic request on {url}")
            try:
                r.get(url, timeout=5)
            except Exception as ex:
                pass
            
        time.sleep(SLEEP_TIME)
        continue
        
    
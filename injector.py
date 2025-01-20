import time
import random
import subprocess
import requests as r
from utils import save_logs

SLEEP_TIME = 1
PROBABILITY_INJECTION = 10 # 10% of probabilities to inject NUMBER_OF_PORTS anomalies each SLEEP_TIME seconds
NUMBER_OF_PORTS = 30
INJECTION_TIME_SLEEP = 5

# It is advisable to disable -sT and -sS by commenting them out as they're detection can be system dependent and a 
# new dataset built and re-trained on the new system may be required for detecting them succesfully.
INJECT_OPTIONS = [
    "-sT",
    "-sS",
    "-sF",
    "-sN",
    "-sX"
]

def should_inject() -> bool:
    """
    Determines if an injection should happen based on PROBABILITY_INJECTION.
    """
    random_number = random.uniform(0, 100)
    return random_number < PROBABILITY_INJECTION

def choose_random_port():
    return random.randint(1, 65_535)

def run_nmap(IP_ADDRESS, OPTION):
    subprocess.call(["nmap", IP_ADDRESS , "-p", f'0-{NUMBER_OF_PORTS}', OPTION], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    
def run_injector(IP_ADDRESS='127.0.0.1'):
    while True:
        injected = False
        
        message = ""
        if should_inject():
            option = random.choices(INJECT_OPTIONS)[0]
            message = f"[INJECTOR] Running NMAP on first {NUMBER_OF_PORTS} ports -> Injector will sleep for {INJECTION_TIME_SLEEP} with attack mode {option}"
            injected = True
            run_nmap(IP_ADDRESS, option)
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
        
        if injected:
            time.sleep(INJECTION_TIME_SLEEP)

        time.sleep(SLEEP_TIME)
        continue
        
    
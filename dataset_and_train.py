import subprocess
import time
import threading
import os 
import hashlib
import sys
from interceptor import capture_packets
from noiser import generate_noise
from utils import run_command , OS_INSTALLATION_PATHS
from export_model import export_model
from datasets.merger import merge_flow_datasets

IP_CAPTURE = '127.0.0.1'

LOCALHOST = 'localhost'

NMAP_COMMANDS_INJECTOR = [
    f"nmap -sT {LOCALHOST} -p 0-2500",
    f"nmap -sS {LOCALHOST} -p 0-2500",
    f"nmap -sF {LOCALHOST} -p 0-2500",
    f"nmap -sN {LOCALHOST} -p 0-2500",
    f"nmap -sX {LOCALHOST} -p 0-2500"
]

INTERFACE = 'lo'
CAPTURE_BAD = os.path.join('datasets','runtime','bad.csv')
CAPTURE_GOOD = os.path.join('datasets','runtime','good.csv')
MERGED =  os.path.join('datasets','runtime','merged.csv')
MODEL_PATH = os.path.join('model','model.pkl')

def calculate_md5(file_path):
    """Calculate the MD5 checksum of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        return f"File '{file_path}' not found."

def produce_dataset_for_this_system():
    stop_event = threading.Event()
    capture_thread = threading.Thread(target=capture_packets, args=(INTERFACE, IP_CAPTURE, CAPTURE_BAD, 1, stop_event), daemon=True)
    capture_thread.start()
    
    time.sleep(3) # give the time to start the monitor
    
    for cmd in NMAP_COMMANDS_INJECTOR:
        run_command(cmd)
    
    md5_checksum = ""
    
    # iterate until the md5 does not change anymore for 2 seconds. if you have other coming connections, this can be a problem
    # you can press ctrl+c to force the loop exiting
    try:
        while md5_checksum != calculate_md5(CAPTURE_BAD):
            print("Monitor is still saving data... if you want to force the proceeding press ctrl+c (do it if you know what you're doing)")
            md5_checksum = calculate_md5(CAPTURE_BAD)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting loop.")
        
    stop_event.set() # stop thread
        
    print("BAD data captured")
    stop_event = threading.Event()
    capture_thread = threading.Thread(target=capture_packets, args=(INTERFACE, IP_CAPTURE, CAPTURE_GOOD, 0, stop_event), daemon=True)
    capture_thread.start()
    
    time.sleep(3) # give the time to start the monitor
    
    # noiser
    generate_noise(target_host=f'{LOCALHOST}')
    
    md5_checksum = ""
    
    # iterate until the md5 does not change anymore for 2 seconds. if you have other coming connections, this can be a problem
    # you can press ctrl+c to force the loop exiting
    try:
        while md5_checksum != calculate_md5(CAPTURE_BAD):
            print("Monitor is still saving data... if you want to force the proceeding press ctrl+c (do it if you know what you're doing)")
            md5_checksum = calculate_md5(CAPTURE_BAD)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting loop.")
        
    stop_event.set() # stop thread
        
    print("Good data captured")
    print("Merging")
    merge_flow_datasets(CAPTURE_BAD, CAPTURE_GOOD, MERGED)

    
if __name__ == "__main__":
    
    no_strict_check_flag = "--no-strict-check" in sys.argv if len(sys.argv) > 1 else False
    
    if not any(os.path.exists(os.path.join(x, "nmap")) for x in OS_INSTALLATION_PATHS):
        print("[bold red]Nmap is required to be installed on the host[/bold red]")
        sys.exit(-1)
    
    if not no_strict_check_flag:
    
        if os.geteuid() != 0:
            print("[bold red]Pyshark needs root privileges for capturing data on interfaces[/bold red]")
            sys.exit(-1)
            
    produce_dataset_for_this_system()
    export_model(dataset_path=MERGED, model_path=MODEL_PATH)
    print(f"Model Exported in {MODEL_PATH}")
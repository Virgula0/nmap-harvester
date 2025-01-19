import time
import joblib
from rich.live import Live
from rich.table import Table
from rich.console import Console
import pandas as pd
import datetime
import os
import threading
import signal
import sys
from interceptor import capture_packets
from injector import run_injector
from utils import preprocess_dataset, save_logs, RUNTIME_CAPTURE, OS_INSTALLATION_PATHS

SLEEP_SECONDS = 1
MODEL_PATH = 'model/model.pkl'
ANOMALY_PERCENTAGE = 30

INTERFACE = 'lo' # change this with your interface
IP = "127.0.0.1"

console = Console()

# Graceful shutdown handler
def signal_handler(sig, frame):
    console.print("[bold red]\n[INFO] Shutting down...[/bold red]")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def read_data():
    df = pd.read_csv(RUNTIME_CAPTURE)
    df = preprocess_dataset(df)
    return df

# Generate live output using rich
def generate_output(data, anomaly_detected, normal_count, anomaly_count, normal_percentage, anomaly_percentage):
    table = Table(title=f"Prediction Summary - {datetime.datetime.now()}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Total Samples", str(len(data)))
    table.add_row("Normal Count", str(normal_count))
    table.add_row("Anomaly Count", str(anomaly_count))
    table.add_row("Normal Percentage", f"{normal_percentage:.2f}%")
    table.add_row("Anomaly Percentage", f"{anomaly_percentage:.2f}%")
    table.add_row("Anomaly Detected", "Yes" if anomaly_detected else "No", style="bold red" if anomaly_detected else "bold green")
    
    return table

def main():
    
    no_strict_check_flag = "--no-strict-check" in sys.argv if len(sys.argv) > 1 else False

    # byass check for nmap installed on the host and root privileges
    if not no_strict_check_flag:
        
        if not any(os.path.exists(os.path.join(x, "nmap")) for x in OS_INSTALLATION_PATHS):
            console.print("[bold red]Nmap is required to be installed on the host[/bold red]")
            sys.exit(-1)
    
        if os.geteuid() != 0:
            console.print("[bold red]Pyshark needs root privileges for capturing data on interfaces[/bold red]")
            sys.exit(-1)
    
    model = joblib.load(MODEL_PATH)
    
    if not model:
        console.print("[bold red]Unable to load the model[/bold red]")
        sys.exit(-1)
    
    console.print(f"[bold green][INFO] Model loaded successfully! {type(model)}[/bold green]")
    
    if os.path.exists(RUNTIME_CAPTURE):
        os.remove(RUNTIME_CAPTURE)
    
    # Start background threads
    capture_thread = threading.Thread(target=capture_packets, args=(INTERFACE, IP, RUNTIME_CAPTURE), daemon=True)
    capture_thread.start()
    
    injector_thread = threading.Thread(target=run_injector, daemon=True)
    injector_thread.start()
    
    time.sleep(SLEEP_SECONDS) # wait a second before proceeding
    
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            if not os.path.exists(RUNTIME_CAPTURE):
                console.print(f"[bold red][ERROR] No runtime capture file found, retrying in {SLEEP_SECONDS} sec[/bold red]")
                time.sleep(SLEEP_SECONDS)
                continue
            
            data = read_data()
            if data.empty:
                console.print("[bold yellow][INFO] Dataframe empty, waiting for data...[/bold yellow]")
                time.sleep(SLEEP_SECONDS)
                continue
            
            predictions = model.predict(data)
            normal_count = sum(1 for p in predictions if p == 0)
            anomaly_count = sum(1 for p in predictions if p == 1)
            total = len(predictions)
            normal_percentage = (normal_count / total) * 100
            anomaly_percentage = (anomaly_count / total) * 100
            
            anomaly_detected = anomaly_percentage >= ANOMALY_PERCENTAGE
            
            if anomaly_detected:
                console.print("[bold red][WARN] Detected anomaly![/bold red]")
            else:
                console.print("[bold green][INFO] System normal![/bold green]")
            
            live.update(generate_output(data, anomaly_detected, normal_count, anomaly_count, normal_percentage, anomaly_percentage))
            
            result_message = (
                f"Total samples: {total}\n"
                f"Normal: {normal_count} ({normal_percentage:.2f}%)\n"
                f"Anomalies: {anomaly_count} ({anomaly_percentage:.2f}%)\n"
                f"ANOMALY DETECTED? {anomaly_detected}\n",
            )
            
            save_logs(result_message)
            time.sleep(SLEEP_SECONDS)

if __name__ == '__main__':
    main()

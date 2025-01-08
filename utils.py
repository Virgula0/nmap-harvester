import time 
import pandas as pd

LOG_FILE = 'logs'
RUNTIME_CAPTURE = 'datasets/runtime/capture.csv'

# Utility function for time measurement
def current_ms() -> int:
    return round(time.time() * 1000)

def preprocess_dataset(df: pd.DataFrame):
    """
    Preprocess dataset.
    Converts timestamps, categorical features, and binary flags into numerical features.
    Removes source and destination IPs and ports from classification.
    """
    
    df.drop(columns=['start_request_time', 'end_request_time'], inplace=True)
    df.drop(columns=['start_response_time', 'end_response_time'], inplace=True)
    
    df.drop(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port'], inplace=True)
    
    flag_columns = ['SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH']
    for flag in flag_columns:
        df[flag] = df[flag].astype(int)
    
    df['duration'] = df['duration'].astype(float)
    
    if 'label' in df.columns: # if label exists for training purposes
        df['label'] = df['label'].astype(int)
        
    return df

# Save logs to a file
def save_logs(log_message):
    with open(LOG_FILE, 'a') as log_file:
        for x in log_message:
            log_file.write(x)
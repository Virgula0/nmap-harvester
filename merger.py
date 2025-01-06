import pandas as pd

def merge_flow_datasets(file1, file2, output_file):
    """
    Merge two datasets with specific flow-related features.

    Parameters:
        file1 (str): Path to the first CSV file.
        file2 (str): Path to the second CSV file.
        output_file (str): Path to save the merged CSV file.
    """
    try:
        # Read the datasets
        df1 = pd.read_csv(file1)
        df2 = pd.read_csv(file2)
        
        # Validate required columns
        required_columns = {
            "timestamp_start", "timestamp_end", "flow_key",
            "src_ports", "dst_ports", "packet_count",
            "tcp_flags_pattern", "label"
        }
        
        if not required_columns.issubset(df1.columns) or not required_columns.issubset(df2.columns):
            raise ValueError("Both datasets must contain the required columns: "
                             f"{', '.join(required_columns)}")
        
        # Append the two datasets
        merged_df = pd.concat([df1, df2], ignore_index=True)
        
        # Remove duplicates based on the 'flow_key' column
        merged_df = merged_df.drop_duplicates(subset=['flow_key'])
        
        # Save the merged dataset
        merged_df.to_csv(output_file, index=False)
        
        print(f"[SUCCESS] Merged dataset saved as '{output_file}'")
    
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e.filename}")
    except pd.errors.EmptyDataError:
        print("[ERROR] One of the files is empty.")
    except ValueError as e:
        print(f"[ERROR] {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Define file paths
    file1 = 'datasets/packets_scan_bad.csv'
    file2 = 'datasets/packets_scan_good.csv'
    output_file = 'merged.csv'
    
    merge_flow_datasets(file1, file2, output_file)

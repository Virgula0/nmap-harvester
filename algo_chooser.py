import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import time

# Utility function for time measurement
def current_ms() -> int:
    return round(time.time() * 1000)


def preprocess_dataset(df: pd.DataFrame):
    """
    Preprocess dataset for binary classification.
    Converts timestamps, categorical features, and binary flags into numerical features.
    Removes source and destination IPs and ports from classification.
    """
    df['start_time'] = pd.to_datetime(df['start_time'])
    df['end_time'] = pd.to_datetime(df['end_time'])
    
    df['start_time'] = df['start_time'].astype('int64') // 10**9
    df['end_time'] = df['end_time'].astype('int64') // 10**9
    
    df.drop(columns=['start_time', 'end_time'], inplace=True)
    
    df.drop(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port'], inplace=True, errors='ignore')
    
    flag_columns = ['SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH']
    for flag in flag_columns:
        df[flag] = df[flag].astype(int)
    
    df['vertical_scan'] = df['vertical_scan'].astype(int)
    df['horizontal_scan'] = df['horizontal_scan'].astype(int)
    
    # 5️⃣ Ensure No Missing Values
    df.fillna(0, inplace=True)

    
    return df


# Main script
if __name__ == "__main__":
    # Load Dataset
    df = pd.read_csv('./merged.csv')
    print(f"Dataset loaded with {len(df)} records.")

    # Preprocess Dataset
    df = preprocess_dataset(df)
    print("Dataset preprocessed successfully.")
    print(df.head())

    # Separate features and labels
    X = df.drop(columns=['label'])
    y = df['label']

    # Train/Test Split
    train_data, test_data, train_label, test_label = train_test_split(
        X, y, test_size=0.1, shuffle=True
    )

    print("Dataset split into training and testing sets.")

    # Choose Classifier
    clf = RandomForestClassifier(n_estimators=10)

    # Train Classifier
    start_train = current_ms()
    clf.fit(train_data, train_label)
    end_train = current_ms()
    print(f"Training completed in {end_train - start_train} ms.")

    # Predict on Test Data
    start_predict = current_ms()
    predicted_labels = clf.predict(test_data)
    end_predict = current_ms()
    print(f"Prediction completed in {end_predict - start_predict} ms.")

    # Evaluate Model
    acc_score = accuracy_score(test_label, predicted_labels)
    print("Accuracy: %.3f" % acc_score)

    # Handle Confusion Matrix
    cm = confusion_matrix(test_label, predicted_labels)
    if cm.shape == (1, 1):
        if np.unique(test_label)[0] == 0:
            tn, fp, fn, tp = cm[0][0], 0, 0, 0
        else:
            tn, fp, fn, tp = 0, 0, 0, cm[0][0]
    elif cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        raise ValueError(f"Unexpected confusion matrix shape: {cm.shape}")

    print("Confusion Matrix Results:")
    print("True Positives (TP):", tp)
    print("True Negatives (TN):", tn)
    print("False Positives (FP):", fp)
    print("False Negatives (FN):", fn)

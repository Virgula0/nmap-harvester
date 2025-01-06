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

# Preprocessing function
def preprocess_dataset(df: pd.DataFrame):
    """
    Preprocess dataset for binary classification.
    Converts timestamps, list fields, and text fields into numerical features.
    """
    # 1️⃣ Handle timestamps
    df['timestamp_start'] = pd.to_datetime(df['timestamp_start']).astype('int64') // 10**9
    df['timestamp_end'] = pd.to_datetime(df['timestamp_end']).astype('int64') // 10**9
    
    # Create a duration feature
    df['duration'] = df['timestamp_end'] - df['timestamp_start']
    df.drop(columns=['timestamp_start', 'timestamp_end'], inplace=True)

    df['flow_key'] = df['flow_key'].astype('category').cat.codes

    df['src_ports_count'] = df['src_ports'].apply(lambda x: len(eval(x)))
    df['dst_ports_count'] = df['dst_ports'].apply(lambda x: len(eval(x)))
    df.drop(columns=['src_ports', 'dst_ports'], inplace=True)

    def flatten_flags(pattern):
        flags = eval(pattern)
        return np.mean(flags, axis=0) if flags else [0] * 6

    flags_df = df['tcp_flags_pattern'].apply(flatten_flags).apply(pd.Series)
    flags_df.columns = [f"tcp_flag_{i}" for i in range(flags_df.shape[1])]
    df = pd.concat([df, flags_df], axis=1)
    df.drop(columns=['tcp_flags_pattern'], inplace=True)

    return df


# Main script
if __name__ == "__main__":
    # Load Dataset
    df = pd.read_csv('./train_datasets/merged.csv')
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
        X, y, test_size=0.75, shuffle=True
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

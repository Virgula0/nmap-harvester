from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, matthews_corrcoef
from utils import preprocess_dataset
import pandas as pd
import joblib

if __name__== "__main__":
    df = pd.read_csv('./datasets/train/merged.csv')
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

    clf = XGBClassifier(n_estimators=210)
    
    clf.fit(train_data, train_label)
    
    predicted_labels = clf.predict(test_data)  # Supervised/unsupervised prediction

    # Evaluate Model
    acc_score = accuracy_score(test_label, predicted_labels)
    mcc = matthews_corrcoef(test_label, predicted_labels)

    tn, fp, fn, tp = confusion_matrix(test_label, predicted_labels).ravel()
    
    print(f"Accuracy {acc_score}, MCC {mcc}, TN: {tn} FP: {fp} FN: {fn} TP: {tp}")
    
    joblib.dump(clf, "./model/model.pkl")
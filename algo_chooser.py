import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, matthews_corrcoef

from utils import preprocess_dataset , current_ms
from classifiers import init_classifiers, suppress_stdout, SUPERVISED

# Suppress ABOD warnings and LinearDiscriminantAnalysis (Wanings depends on the dataset)
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Main script
if __name__ == "__main__":
    # Load Dataset
    df = pd.read_csv('./datasets/tests/merged.csv')
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
        
    # Track the best classifier based on Accuracy and MCC and prediction time
    best_acc = float('-inf')
    best_acc_clf = None
    best_acc_n = None

    best_mcc = float('-inf')
    best_mcc_clf = None
    best_mcc_n = None
    
    best_predict_time = float('+inf')
    best_predict_time_clf = None
    
    classifiers = init_classifiers(n_features=len(X.columns))

    # Evaluate Classifiers
    for clf, clf_type in classifiers:
        
        try:
            # Train Classifier
            with suppress_stdout():
                start_train = current_ms()
                if clf_type == SUPERVISED:
                    clf.fit(train_data, train_label)  # Supervised training
                else:
                    clf.fit(train_data)  # Unsupervised training (no labels)
                end_train = current_ms()

            # Predict on Test Data
            start_predict = current_ms()
            predicted_labels = clf.predict(test_data)  # Supervised/unsupervised prediction
            end_predict = current_ms()

            # Calculate time taken
            train_time = end_train - start_train
            predict_time = end_predict - start_predict

            # Evaluate Model
            acc_score = accuracy_score(test_label, predicted_labels)
            mcc = matthews_corrcoef(test_label, predicted_labels)

            tn, fp, fn, tp = confusion_matrix(test_label, predicted_labels).ravel()

            prediction_time = end_predict - start_predict
            train_time = end_train - start_train
            
            print(
                "%s (n_estimators=%s): Accuracy: %.4f, Train time: %dms, Prediction time: %dms, MCC: %.6f, TP: %d, TN: %d, FN: %d, FP: %d"
                % (
                    getattr(clf, '_model_name', clf.__class__.__name__),
                    getattr(clf, 'n_estimators', 'N/A'),
                    acc_score,
                    train_time,
                    prediction_time,
                    mcc,
                    tp,
                    tn,
                    fn,
                    fp,
                )
            )

            # Track the best classifier based on Accuracy
            if acc_score >= best_acc:
                best_acc = acc_score
                best_acc_clf = clf
                best_acc_n = getattr(clf, 'n_estimators', 'N/A')

            # Track the best classifier based on MCC
            if mcc >= best_mcc:
                best_mcc = mcc
                best_mcc_clf = clf
                best_mcc_n = getattr(clf, 'n_estimators', 'N/A')
                
            if prediction_time <= best_predict_time and prediction_time > 0:
                best_predict_time = prediction_time
                best_predict_time_clf = clf

        except Exception as e:
            print(f"Error evaluating classifier {clf.__class__.__name__}: {e}")

    # Print the best classifier based on Accuracy
    print("\nBest Classifier based on Accuracy")
    print(f"Classifier: {best_acc_clf.__class__.__name__}")
    print(f"n_estimators: {best_acc_n}")
    print(f"Accuracy Score: {best_acc:.4f}")

    # Print the best classifier based on MCC
    print("\nBest Classifier based on MCC")
    print(f"Classifier: {best_mcc_clf.__class__.__name__}")
    print(f"n_estimators: {best_mcc_n}")
    print(f"MCC Score: {best_mcc:.6f}")
    
    # Print the best classifier based on prediction time
    print("\nBest Classifier based on prediction time")
    print(f"Classifier: {best_predict_time_clf.__class__.__name__}")
    print(f"Time : {best_predict_time:.6f}ms")
    
    # Export model prefering best accuracy model over best_mcc
    # I comment the dump because, XGBClassifier does not provide the best accuracy every time
    # The reason why it has been chosen over other models can be found in README.md

    # joblib.dump(best_acc_clf, "./model/model.pkl")
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, matthews_corrcoef

from sklearn.ensemble import (
    VotingClassifier,
    StackingClassifier,
    RandomForestClassifier,
    GradientBoostingClassifier,
    AdaBoostClassifier,
    BaggingClassifier,
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
)
from sklearn.linear_model import (
    LogisticRegression,
    RidgeClassifier,
    SGDClassifier,
    Perceptron,
    PassiveAggressiveClassifier,
)
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.tree import DecisionTreeClassifier, ExtraTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis, QuadraticDiscriminantAnalysis
from sklearn.svm import SVC, LinearSVC, NuSVC
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

import joblib

from utils import preprocess_dataset , current_ms

# Main script
if __name__ == "__main__":
    # Load Dataset
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

    print("Dataset split into training and testing sets.")
        
    classifiers = [
        # Ensemble Classifiers
        VotingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ]),
        StackingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ], final_estimator=RandomForestClassifier(n_estimators=10)),
        BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=10),
        AdaBoostClassifier(n_estimators=50),
        GradientBoostingClassifier(n_estimators=100),
        ExtraTreesClassifier(n_estimators=100),
        HistGradientBoostingClassifier(),
        CatBoostClassifier(verbose=0),
        LGBMClassifier(verbose=-1),
        
        # Linear Models
        LogisticRegression(max_iter=1000),
        RidgeClassifier(),
        SGDClassifier(max_iter=1000, tol=1e-3),
        Perceptron(),
        PassiveAggressiveClassifier(),
        
        # Tree-Based Models
        DecisionTreeClassifier(),
        ExtraTreeClassifier(),
        
        # Naive Bayes Classifiers
        GaussianNB(),
        MultinomialNB(),
        BernoulliNB(),
        
        # Discriminant Analysis
        LinearDiscriminantAnalysis(solver='lsqr'),
        LinearDiscriminantAnalysis(solver='eigen'),

        QuadraticDiscriminantAnalysis(),
        
        # Support Vector Machines
        SVC(kernel='rbf', probability=True),
        SVC(kernel='linear', probability=True),
        LinearSVC(max_iter=10000),
        NuSVC(probability=True),
    ]
    
    
    # Dynamically add other classifiers instances with different number of parameters
    
    classifiers.extend([
        KNeighborsClassifier(n_neighbors=n) for n in range(1, 211)
    ])
    
    classifiers.extend([
        RandomForestClassifier(n_estimators=n) for n in range(1, 211)
    ])
    
    classifiers.extend([
        XGBClassifier(n_estimators=n) for n in range(1, 211)
    ])
    
     # Track the best classifier based on Accuracy and MCC
    best_acc = float('-inf')
    best_acc_clf = None
    best_acc_n = None

    best_mcc = float('-inf')
    best_mcc_clf = None
    best_mcc_n = None

    # Evaluate Classifiers
    for clf in classifiers:
        try:
            # Train Classifier
            start_train = current_ms()
            clf.fit(train_data, train_label)
            end_train = current_ms()

            # Predict on Test Data
            start_predict = current_ms()
            predicted_labels = clf.predict(test_data)
            end_predict = current_ms()

            # Evaluate Model
            acc_score = accuracy_score(test_label, predicted_labels)
            mcc = matthews_corrcoef(test_label, predicted_labels)

            tn, fp, fn, tp = confusion_matrix(test_label, predicted_labels).ravel()

            print(
                "%s (n_estimators=%s): Accuracy: %.4f, Train time: %dms, Prediction time: %dms, MCC: %.6f, TP: %d, TN: %d, FN: %d, FP: %d"
                % (
                    clf.__class__.__name__,
                    getattr(clf, 'n_estimators', 'N/A'),
                    acc_score,
                    end_train - start_train,
                    end_predict - start_predict,
                    mcc,
                    tp,
                    tn,
                    fn,
                    fp,
                )
            )

            # Track the best classifier based on Accuracy
            if acc_score > best_acc:
                best_acc = acc_score
                best_acc_clf = clf
                best_acc_n = getattr(clf, 'n_estimators', 'N/A')

            # Track the best classifier based on MCC
            if mcc >= best_mcc:
                best_mcc = mcc
                best_mcc_clf = clf
                best_mcc_n = getattr(clf, 'n_estimators', 'N/A')

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
    
    # Export model using best mcc score
    
    joblib.dump(best_mcc_clf, "./model/model.pkl")
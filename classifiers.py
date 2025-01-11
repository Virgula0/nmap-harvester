from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.feature_selection import VarianceThreshold

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

from pyod.models.abod import ABOD
from pyod.models.iforest import IForest
from pyod.models.cblof import CBLOF
from pyod.models.sod import SOD
from pyod.models.feature_bagging import FeatureBagging
from pyod.models.auto_encoder import AutoEncoder
from pyod.models.deep_svdd import DeepSVDD

from contextlib import contextmanager
import os 
import sys

SUPERVISED = "supervised"
UNSUPERVISED = "unsupervised"

def init_classifiers(n_features):
    classifiers = []
    
    classifiers.extend([
        (VotingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ]), SUPERVISED),
        (StackingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ], final_estimator=RandomForestClassifier(n_estimators=10)), SUPERVISED),
        (BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=10), SUPERVISED),
        (AdaBoostClassifier(n_estimators=50), SUPERVISED),
        (GradientBoostingClassifier(n_estimators=100), SUPERVISED),
        (ExtraTreesClassifier(n_estimators=100), SUPERVISED),
        (HistGradientBoostingClassifier(), SUPERVISED),
        (CatBoostClassifier(verbose=0), SUPERVISED),
        (LGBMClassifier(verbose=-1), SUPERVISED),
        (LogisticRegression(max_iter=1000), SUPERVISED),
        (RidgeClassifier(), SUPERVISED),
        (SGDClassifier(max_iter=1000, tol=1e-3), SUPERVISED),
        (Perceptron(), SUPERVISED),
        (PassiveAggressiveClassifier(), SUPERVISED),
        (DecisionTreeClassifier(), SUPERVISED),
        (ExtraTreeClassifier(), SUPERVISED),
        (GaussianNB(), SUPERVISED),
        (MultinomialNB(), SUPERVISED),
        (BernoulliNB(), SUPERVISED),
        (LinearDiscriminantAnalysis(solver='lsqr'), SUPERVISED),
        (LinearDiscriminantAnalysis(solver='eigen'), SUPERVISED),
        (QuadraticDiscriminantAnalysis(), SUPERVISED),
        (SVC(kernel='rbf', probability=True), SUPERVISED),
        (SVC(kernel='linear', probability=True), SUPERVISED),
        (LinearSVC(max_iter=10000), SUPERVISED),
        (NuSVC(probability=True), SUPERVISED),
    ])
    
    classifiers.extend([
        (KNeighborsClassifier(n_neighbors=n), SUPERVISED)
        for n in range(1, 211, 2) # only odd number of neighbors
    ])
    
    classifiers.extend([
        (RandomForestClassifier(n_estimators=n), SUPERVISED)
        for n in range(1, 211)
    ])
    
    classifiers.extend([
        (XGBClassifier(n_estimators=n), SUPERVISED)
        for n in range(1, 211)
    ])
    
    classifiers.extend([
        (ABOD(n_neighbors=n, contamination=0.5), UNSUPERVISED)
        for n in range(5, 11, 5)  # Smaller range
    ])

    # Add IForest classifiers with preprocessing pipeline
    classifiers.extend([
        (add_model_name(Pipeline([
            ('to_numpy', FunctionTransformer(to_numpy)),  # Converts DataFrame to NumPy array
            ('iforest', IForest(n_estimators=n, contamination=0.1))  # Isolation Forest
        ]), name=f"IForest (n_estimators={n})"), UNSUPERVISED)
        for n in range(50, 201, 50)
    ])
    
    classifiers.extend([
        (CBLOF(contamination=c, n_clusters=n), UNSUPERVISED)
        for c in [0.05, 0.1, 0.2]
        for n in range(5, 21, 5)
    ])
    
    classifiers.extend([
        (add_model_name(
            Pipeline([
                ('preprocessor', FunctionTransformer(sod_preprocess_data)),  # Preprocessing step
                ('sod', SOD(n_neighbors=n, ref_set=r, contamination=c))  # SOD model
            ]),
            name=f"SOD (n_neighbors={n}, ref_set={r}, contamination={c})"
        ), UNSUPERVISED)
        for n in range(5, 10, 5) # n_neighbors
        for r in range(2, n)   # Ensure ref_set < n_neighbors
        for c in [0.05, 0.1, 0.2]  # Contamination levels
    ])
    
    classifiers.extend([
        (FeatureBagging(contamination=c, n_estimators=n), UNSUPERVISED)
        for c in [0.05, 0.1, 0.2]
        for n in range(5, 11, 5)
    ])
    
    # CNNs
    classifiers.extend([
        (AutoEncoder(contamination=c), UNSUPERVISED)
        for c in [0.05, 0.1, 0.2]
    ])

    classifiers.extend([
        (DeepSVDD(n_features=n_features, contamination=c), UNSUPERVISED)
        for c in [0.05, 0.1, 0.2]
    ])

    return classifiers

@contextmanager
def suppress_stdout():
    with open(os.devnull, 'w') as devnull:
        old_stdout = sys.stdout
        try:
            sys.stdout = devnull
            yield
        finally:
            sys.stdout = old_stdout

def sod_preprocess_data(X):
    selector = VarianceThreshold(threshold=0.0)
    scaler = StandardScaler()
    X = selector.fit_transform(X)
    X = scaler.fit_transform(X)
    return X

# Define a transformer to convert Pandas DataFrame to NumPy array
def to_numpy(X):
    return X.to_numpy()

def add_model_name(pipeline, name):
    pipeline._model_name = name
    return pipeline
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import classification_report, f1_score
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

from sklearn.ensemble import (
    RandomForestClassifier,
    AdaBoostClassifier,
    GradientBoostingClassifier,
    BaggingClassifier,
    ExtraTreesClassifier
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from xgboost import XGBClassifier

train_data = pd.read_csv('NSLKDD-DataSet/KDDTrain+.txt', header=None)
test_data = pd.read_csv('NSLKDD-DataSet/KDDTest-21.txt', header=None)

columns = [
    "duration", "protocol_type", "service",
    "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations","num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

train_data.columns = columns
test_data.columns = columns

train_data.drop(['difficulty_level'], axis=1, inplace=True)
test_data.drop(['difficulty_level'], axis=1, inplace=True)

categorical_cols = ['protocol_type', 'service', 'flag']
encoder = LabelEncoder()
for col in categorical_cols:
    train_data[col] = encoder.fit_transform(train_data[col])
    test_data[col] = encoder.transform(test_data[col])

attack_map = {
    'normal': 'normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R'
}

train_data['attack_type'] = train_data['label'].map(attack_map)
test_data['attack_type'] = test_data['label'].map(attack_map)

train_data.dropna(subset=['attack_type'], inplace=True)
test_data.dropna(subset=['attack_type'], inplace=True)

# R2L ve U2R kaldırma
train_data = train_data[~train_data['attack_type'].isin(['R2L', 'U2R'])]
test_data = test_data[~test_data['attack_type'].isin(['R2L', 'U2R'])]

selected_features = [
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes'
]

train_X = train_data[selected_features]
test_X = test_data[selected_features]
train_y = train_data['attack_type']
test_y = test_data['attack_type']

label_encoder = LabelEncoder()
train_y_encoded = label_encoder.fit_transform(train_y)
test_y_encoded = label_encoder.transform(test_y)

smote = SMOTE(random_state=42)
train_X_balanced, train_y_balanced = smote.fit_resample(train_X, train_y_encoded)

models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'KNN': KNeighborsClassifier(n_neighbors=5),
    'Logistic Regression': LogisticRegression(max_iter=50),
    'AdaBoost': AdaBoostClassifier(n_estimators=50, random_state=42),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
    'Bagging': BaggingClassifier(n_estimators=50, random_state=42),
    'Extra Trees': ExtraTreesClassifier(n_estimators=100, random_state=42),
    'Naive Bayes': GaussianNB(),
    'XGBoost': XGBClassifier(n_estimators=100, use_label_encoder=False, eval_metric='mlogloss', random_state=42)
}

f1_scores = {}

for model_name, model in models.items():
    print(f"==> Model: {model_name}")
    model.fit(train_X_balanced, train_y_balanced)
    y_pred = model.predict(test_X)
    score = f1_score(test_y_encoded, y_pred, average='weighted')
    f1_scores[model_name] = score
    print(classification_report(test_y_encoded, y_pred))

plt.figure(figsize=(10, 6))
sns.barplot(x=list(f1_scores.values()), y=list(f1_scores.keys()), palette="viridis")
plt.xlabel("Weighted F1-Score")
plt.title("Model Performans Karşılaştırması (SCAPY Features)")
plt.tight_layout()
plt.show()
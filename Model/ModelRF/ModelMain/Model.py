import pandas as pd
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from imblearn.over_sampling import SMOTE

print("Veri yükleniyor....")
train_data = pd.read_csv('NSLKDD-DataSet/KDDTrain+.txt', header=None)
test_data = pd.read_csv('NSLKDD-DataSet/KDDTest-21.txt', header=None)

columns = [
    "duration", "protocol_type",
    "service","flag",
    "src_bytes", "dst_bytes",
    "land", "wrong_fragment",
    "urgent", "hot",
    "num_failed_logins", "logged_in",
    "num_compromised", "root_shell",
    "su_attempted", "num_root",
    "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count",
    "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
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
    
    'back': 'DoS',
    'land': 'DoS',
    'neptune': 'DoS',
    'pod': 'DoS',
    'smurf': 'DoS',
    'teardrop': 'DoS',

    'ipsweep': 'Probe', 
    'nmap': 'Probe', 
    'portsweep': 'Probe', 
    'satan': 'Probe',

    'ftp_write': 'R2L', 
    'guess_passwd': 'R2L', 
    'imap': 'R2L', 
    'multihop': 'R2L',
    'phf': 'R2L', 
    'spy': 'R2L', 
    'warezclient': 'R2L', 
    'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 
    'loadmodule': 'U2R', 
    'perl': 'U2R', 
    'rootkit': 'U2R'
}

train_data['attack_type'] = train_data['label'].map(attack_map)
test_data['attack_type'] = test_data['label'].map(attack_map)

train_data.dropna(subset=['attack_type'], inplace=True)
test_data.dropna(subset=['attack_type'], inplace=True)

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
train_X_balanced = pd.DataFrame(train_X_balanced, columns=selected_features)

MODEL_DIR = "Model/ModelRF/ModelMain"
MODEL_FILE = os.path.join(MODEL_DIR, "model_rf_no_u2r_r2l_final.joblib")
os.makedirs(MODEL_DIR, exist_ok=True)

print("Model yükleniyor veya eğitiliyor...")
if os.path.exists(MODEL_FILE):
    model = joblib.load(MODEL_FILE)
else:
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42
    )
    model.fit(train_X_balanced, train_y_balanced)
    joblib.dump(model, MODEL_FILE)
    print(f"Model '{MODEL_FILE}' dosyasına kaydedildi.")

y_pred = model.predict(test_X)
print("\nSınıflandırma Sonuçları (Test Seti):")
print(classification_report(test_y_encoded, y_pred, target_names=label_encoder.classes_))

cm = confusion_matrix(test_y_encoded, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=label_encoder.classes_)
disp.plot(cmap="Blues", values_format="d")
plt.title("Confusion Matrix (Test Seti)")
plt.show()

feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'Feature': selected_features,
    'Importance': feature_importance
}).sort_values(by='Importance', ascending=False)

plt.figure(figsize=(10, 6))
sns.barplot(x='Importance', y='Feature', data=importance_df, palette="viridis")
plt.title('Feature Importance (Random Forest)')
plt.tight_layout()
plt.show()

# model_rf_no_u2r_r2l -> %93+

# --Çıkarılan özellikler (Flow bazlı, Scapy ile yakalanamaz):
# 'duration', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate'
# 'wrong_fragment' özellik önemi çok düşük çıktığından bunu da elimine ediyoruz.

# model_rf_no_u2r_r2l_final -> %92~93 (Özellikler çıkarıldıktan sonra)
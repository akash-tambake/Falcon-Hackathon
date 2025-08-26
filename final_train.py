import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
# Load dataset
df = pd.read_csv("D:\\MATH SOLNS\\New folder\\dns_binary_realtime_training_data.csv")

# Convert string/categorical features to numeric
for col in df.columns:
    if df[col].dtype == 'object':
        df[col] = df[col].astype(str).fillna("missing")
        df[col] = LabelEncoder().fit_transform(df[col])

# Separate features and labels
X = df.drop(columns=["Class"])
y_raw = df["Class"]
y = y_raw.map({0: "benign", 1: "malware"})  # Human-readable labels

# Compute class weights to handle any imbalance

class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y), y=y)

class_weight_dict = {"benign": class_weights[0], "malware": class_weights[1]}

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Train a more optimized Random Forest model
model = RandomForestClassifier(
    n_estimators=300,                # more trees → better generalization
    max_depth=25,                    # control tree growth
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight=class_weight_dict, # deal with imbalance
    random_state=42,
    n_jobs=-1,
    oob_score=True                  # enable out-of-bag error estimation
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\n[+] Classification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred, labels=["benign", "malware"])
sns.heatmap(cm, annot=True, fmt="d", xticklabels=["benign", "malware"], yticklabels=["benign", "malware"], cmap="Blues")
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

# Save model
joblib.dump(model, "1dns_binary_rf_model_optimized.joblib")
print("[+] Optimized model saved as dns_binary_rf_model_optimized.joblib")

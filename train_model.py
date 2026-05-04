import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend — no display required
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report, accuracy_score,
    ConfusionMatrixDisplay, confusion_matrix
)
import time

print("Initializing AI-IDS Model Training...")

# The robust 11 features we can accurately calculate in real-time
USE_FEATURES = [
    'Destination Port', 
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Length of Fwd Packets',
    'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 
    'Fwd Packet Length Mean', 
    'Fwd Packet Length Std',
    'Flow Bytes/s', 
    'Flow Packets/s', 
    'Average Packet Size',
    'Attack Type' # Label
]

print(f"Loading dataset with {len(USE_FEATURES)-1} features...")
start_time = time.time()
# memory efficient loading of just the columns we need
df = pd.read_csv('cicids2017_cleaned.csv', usecols=USE_FEATURES)

print(f"Dataset loaded in {time.time() - start_time:.2f}s. Shape: {df.shape}")

# Clean infinite and missing values created by zero division in dataset
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Map labels
# To optimize the classifier and avoid rare classes dropping accuracy, 
# we map the specific attacks to a concise, high-impact set.
def map_attacks(attack):
    attack = attack.lower()
    if 'normal' in attack or 'benign' in attack:
        return 'Normal Traffic'
    elif 'dos' in attack and 'ddos' not in attack:
        return 'DoS'
    elif 'ddos' in attack:
        return 'DDoS'
    elif 'portscan' in attack or 'port scan' in attack:
        return 'Port Scanning'
    elif 'brute' in attack or 'ftp-patator' in attack or 'ssh-patator' in attack:
        return 'Brute Force'
    elif 'web' in attack or 'xss' in attack or 'sql' in attack:
        return 'Web Attacks'
    elif 'bot' in attack:
        return 'Botnet'
    else:
        return 'Other Exploit'

df['Attack Type'] = df['Attack Type'].apply(map_attacks)

print("Attack Distribution in Full Dataset:")
print(df['Attack Type'].value_counts())

# Stratified Sampling to make training fast and balanced (~150,000 rows max if possible)
# We want to keep all minority attacks but cap majority (Normal Traffic, DoS, Port Scanning)
sampled_dfs = []
for attack_type in df['Attack Type'].unique():
    subset = df[df['Attack Type'] == attack_type]
    cap = 40000 if attack_type == 'Normal Traffic' else 20000
    if len(subset) > cap:
        subset = subset.sample(n=cap, random_state=42)
    sampled_dfs.append(subset)

df_sampled = pd.concat(sampled_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"Sampled Dataset Shape: {df_sampled.shape}")
print("Attack Distribution in Sampled Dataset:")
print(df_sampled['Attack Type'].value_counts())

X = df_sampled.drop('Attack Type', axis=1).values
y = df_sampled['Attack Type'].values

# Encode labels for XGBoost
classes = np.unique(y)
class_to_idx = {c: i for i, c in enumerate(classes)}
idx_to_class = {i: c for i, c in enumerate(classes)}
y_encoded = np.array([class_to_idx[l] for l in y])

# Save the mapping
joblib.dump(idx_to_class, 'label_map.pkl')

print("Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'scaler.pkl')

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

# ── TASK 4: Correlation Heatmap ────────────────────────────────────────────────
print("\nGenerating Correlation Heatmap...")
feature_names = USE_FEATURES[:-1]
df_features = pd.DataFrame(X_train, columns=feature_names)
corr = df_features.corr()
plt.figure(figsize=(12, 9))
sns.heatmap(
    corr, annot=True, fmt='.2f', cmap='coolwarm',
    linewidths=0.5, annot_kws={'size': 8},
    xticklabels=feature_names, yticklabels=feature_names
)
plt.title('Feature Correlation Heatmap', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig('correlation_heatmap.png', dpi=150)
plt.close()
print("✅ Saved: correlation_heatmap.png")

# ── TASK 2: Baseline Models ────────────────────────────────────────────────────
print("\nTraining Baseline Models for Comparison...")

dt = DecisionTreeClassifier(max_depth=10, random_state=42)
dt.fit(X_train, y_train)
dt_acc = accuracy_score(y_test, dt.predict(X_test))
print(f"  Decision Tree Accuracy:  {dt_acc:.4%}")

lr = LogisticRegression(max_iter=500, n_jobs=-1, random_state=42)
lr.fit(X_train, y_train)
lr_acc = accuracy_score(y_test, lr.predict(X_test))
print(f"  Logistic Regression Accuracy: {lr_acc:.4%}")

print("Training Ensemble Model (Random Forest + XGBoost)...")
rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
xgb = XGBClassifier(
    n_estimators=100, 
    max_depth=6, 
    learning_rate=0.1, 
    use_label_encoder=False, 
    eval_metric='mlogloss', 
    n_jobs=-1, 
    random_state=42
)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb)],
    voting='soft',
    n_jobs=-1
)

start_time = time.time()
ensemble.fit(X_train, y_train)
print(f"Model trained in {time.time() - start_time:.2f}s.")

print("Evaluating Model...")
y_pred = ensemble.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\nFinal Accuracy: {acc:.4%}")
print("\nClassification Report:")
target_names = [idx_to_class[i] for i in range(len(classes))]
print(classification_report(y_test, y_pred, target_names=target_names))

# ── TASK 2 (continued): Print Model Comparison ────────────────────────────────
print("\n── Model Comparison Summary ──────────────────────────────────────────")
print(f"  Decision Tree:       {dt_acc:.4%}")
print(f"  Logistic Regression: {lr_acc:.4%}")
print(f"  RF+XGBoost Ensemble: {acc:.4%}  ← Best Model")
print("──────────────────────────────────────────────────────────────────────")

# ── TASK 1: Confusion Matrix ───────────────────────────────────────────────────
print("\nGenerating Confusion Matrix...")
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(10, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=target_names)
disp.plot(ax=ax, colorbar=True, cmap='Blues', xticks_rotation=45)
ax.set_title('Confusion Matrix — RF+XGBoost Ensemble', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=150)
plt.close()
print("✅ Saved: confusion_matrix.png")

# ── TASK 3: Feature Importance ────────────────────────────────────────────────
print("\nGenerating Feature Importance Chart...")
# Extract the fitted Random Forest from inside the ensemble
rf_fitted = ensemble.estimators_[0]
importances = rf_fitted.feature_importances_
indices = np.argsort(importances)[::-1]
sorted_features = [feature_names[i] for i in indices]
sorted_importances = importances[indices]

plt.figure(figsize=(10, 6))
bars = plt.barh(sorted_features[::-1], sorted_importances[::-1],
                color=plt.cm.Blues(np.linspace(0.4, 0.9, len(sorted_features))))
plt.xlabel('Importance Score', fontsize=11)
plt.title('Random Forest Feature Importance', fontsize=13, fontweight='bold')
for bar, val in zip(bars, sorted_importances[::-1]):
    plt.text(val + 0.002, bar.get_y() + bar.get_height() / 2,
             f'{val:.3f}', va='center', fontsize=9)
plt.tight_layout()
plt.savefig('feature_importance.png', dpi=150)
plt.close()
print("✅ Saved: feature_importance.png")

print("Saving models...")
joblib.dump(ensemble, 'trained_ids_model.pkl')
joblib.dump(USE_FEATURES[:-1], 'features.pkl')

print("✅ Model Training Complete. Ready for real-time inference.")

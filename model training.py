import os
import json
import glob
import joblib
import numpy as np
import polars as pl
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import IsolationForest
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

# ── FORCE GPU CHECK BEFORE TRAINING ──────────────────────────────────
try:
    # Test allocation on GPU to force an immediate crash if CUDA is broken
    test_matrix = xgb.DMatrix(np.ones((10, 10)), label=np.ones(10))
    xgb.train({"tree_method": "hist", "device": "cuda"}, test_matrix, num_boost_round=1)
    print("✅ GPU verification passed! XGBoost is successfully communicating with CUDA.")
except Exception as e:
    print("❌ GPU Verification Failed! Cannot access CUDA device.")
    print(f"Error details: {e}")
    print("\nAborting execution to prevent CPU fallback.")
    exit(1)

# ── 1 & 2. Targeted Data Loading ───────────────────────────────────────────
DATA_DIR = "./maldroid/maldroid"

# Instead of blindly loading every CSV, we target the highest-signal dataset.
# The 'syscallsbinders' file has 471 dense features, which is perfect for XGBoost.
# If your folder structure is slightly different, just update this exact filename.
target_file = glob.glob(os.path.join(DATA_DIR, "**/*syscallsbinders*.csv"), recursive=True)

if not target_file:
    print(f"❌ Could not find the syscallsbinders dataset in {DATA_DIR}.")
    exit(1)

print(f"Loading targeted dataset: {os.path.basename(target_file[0])}...")

# Load the single best dataset. No concatenation needed!
data = pl.read_csv(target_file[0], infer_schema_length=10000, null_values=[""])
print(f"Loaded successfully! Total rows: {data.shape[0]}, Total columns: {data.shape[1]}")

# ── 3. Find Label Column ──────────────────────────────────────────
label_col = None
for col in ['Label', 'label', 'Class', 'class', 'Category', 'category', 'Type']:
    if col in data.columns:
        label_col = col
        break

if label_col is None:
    print("❌ Could not find a label column. Checked: Label, label, Class, class, Category, category, Type.")
    exit(1)

print(f"Label column identified: {label_col}")
print("Raw label distribution:")
print(data[label_col].value_counts().sort(label_col))

# ── 4. Map Labels to Integers ─────────────────────────────────────
# feature_vectors_syscallsbinders_frequency_5_Cat.csv is from CICMalDroid-2020,
# where 'Class' is already integer-coded 1-5 (not text labels).
# Official category order: 1=Adware, 2=Banking, 3=SMS, 4=Riskware, 5=Benign.
LABEL_MAP = {
    1: 0,  # Adware
    2: 1,  # Banking malware
    3: 2,  # SMS malware
    4: 3,  # Riskware
    5: 4,  # Benign
}
CLASSES = ['Adware', 'Banking', 'SMS_Malware', 'Riskware', 'Benign']

# Sanity check: make sure every raw label value is actually covered by LABEL_MAP.
# This catches typos/extra categories BEFORE training instead of silently
# corrupting or dropping data downstream.
raw_labels = set(data[label_col].drop_nulls().unique().to_list())
unmapped = raw_labels - set(LABEL_MAP.keys())
if unmapped:
    print(f"⚠️  Warning: {len(unmapped)} raw label value(s) not covered by LABEL_MAP: {unmapped}")
    print("    Rows with these values will be dropped. Add them to LABEL_MAP if they should be kept.")

# replace_strict turns anything NOT in LABEL_MAP into null (instead of silently
# leaving it as the original string), so the filter below actually catches it.
data = data.with_columns(
    pl.col(label_col).replace_strict(LABEL_MAP, default=None, return_dtype=pl.Int32).alias('_label')
)

rows_before = data.shape[0]
data = data.filter(pl.col('_label').is_not_null())
rows_dropped = rows_before - data.shape[0]
if rows_dropped:
    print(f"Dropped {rows_dropped} row(s) with unmapped/missing labels.")

y = data['_label'].to_numpy().astype(np.int32)

numeric_cols = [col for col, dtype in zip(data.columns, data.dtypes) if dtype.is_numeric() and col not in [label_col, '_label']]
print(f"Using {len(numeric_cols)} numeric feature columns: {numeric_cols[:10]}{'...' if len(numeric_cols) > 10 else ''}")

X = data.select(numeric_cols).to_numpy().astype(np.float32)
print(f"Feature matrix shape: {X.shape}")

# ── 5. Save Feature Column Names + Label Mapping ───────────────────
with open('feature_columns.json', 'w') as f:
    json.dump(numeric_cols, f)
print(f"Saved {len(numeric_cols)} feature column names to 'feature_columns.json'")

with open('label_map.json', 'w') as f:
    json.dump({'LABEL_MAP': LABEL_MAP, 'CLASSES': CLASSES}, f)
print("Saved label mapping + class names to 'label_map.json'")

# ── 6. Clean Inf/NaN, Train/Test Split, Impute, Scale ──────────────
n_inf = int(np.isinf(X).sum())
if n_inf:
    print(f"Found {n_inf} Inf value(s) in features, converting to NaN before imputation.")
    X[np.isinf(X)] = np.nan

n_nan = int(np.isnan(X).sum())
print(f"Found {n_nan} NaN value(s) in features (median-imputed using train stats only).")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Imputing missing values (median, fit on train only)...")
imputer = SimpleImputer(strategy='median')
X_train = imputer.fit_transform(X_train)
X_test = imputer.transform(X_test)
joblib.dump(imputer, 'median_imputer.pkl')

print("Scaling data features...")
scaler = MinMaxScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
joblib.dump(scaler, 'minmax_scaler.pkl')

sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

# ── 7. Train XGBoost strictly on GPU ──────────────────────────────
print("\nTraining XGBoost strictly on GPU...")
clf = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    tree_method='hist',
    device='cuda',            # Forces execution on the CUDA device
    eval_metric='mlogloss',
    random_state=42
)

clf.fit(X_train, y_train, sample_weight=sample_weights, eval_set=[(X_test, y_test)], verbose=True)

y_pred = clf.predict(X_test)
print(f"\nFinal Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=CLASSES))

joblib.dump(clf, 'xgboost_maldroid.pkl')
print("✅ XGBoost Model saved locally as 'xgboost_maldroid.pkl'!")

# ── 8. Train Isolation Forest (Anomaly Detection) ──────────────────
print("\nTraining Isolation Forest...")
X_benign = X_train[y_train == 4]
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
iso.fit(X_benign)

joblib.dump(iso, 'isolation_forest.pkl')
print("✅ Isolation Forest saved locally as 'isolation_forest.pkl'!")
print("\n🎉 All tasks completed successfully on local environment!")
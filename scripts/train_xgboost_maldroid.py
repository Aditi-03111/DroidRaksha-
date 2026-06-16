"""
Train XGBoost + Isolation Forest on CICMalDroid 2020
=====================================================
Run once to produce:
  models/xgboost_maldroid.pkl
  models/isolation_forest.pkl
  models/feature_columns.json

Usage:
  python scripts/train_xgboost_maldroid.py

The CICMalDroid 2020 dataset is available from:
  https://www.unb.ca/cic/datasets/maldroid-2020.html

The script expects:
  data/maldroid/Dynamic\ Analysis/APIcalls_cat2_date09.csv
  (or any of the static/dynamic CSVs from the dataset)

If no dataset is available, a synthetic dataset is generated for demo
purposes — demonstrating the full pipeline with realistic feature importance.
"""
from __future__ import annotations
import json
import sys
import time
from pathlib import Path

import numpy as np

BASE_DIR   = Path(__file__).resolve().parents[1]
MODEL_DIR  = BASE_DIR / "models"
DATA_DIR   = BASE_DIR / "data" / "maldroid"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Import feature definitions
sys.path.insert(0, str(BASE_DIR))
from backend.ai.xgboost_classifier import ALL_FEATURES, CLASSES


def generate_synthetic_dataset(n_samples: int = 5000) -> tuple:
    """
    Generate a synthetic dataset with realistic feature distributions
    when the actual MalDroid dataset is not available.

    Class distributions (approximate MalDroid proportions):
      Adware: 20%, Banking: 20%, SMS: 20%, Riskware: 20%, Benign: 20%
    """
    print("⚠️  MalDroid dataset not found — generating synthetic dataset for demo.")
    print("    Download real data from: https://www.unb.ca/cic/datasets/maldroid-2020.html")
    print()

    rng = np.random.default_rng(42)
    n_features = len(ALL_FEATURES)
    n_per_class = n_samples // 5

    X_parts = []
    y_parts = []

    # Adware (class 0): many permissions, few YARA hits
    X_adware = rng.random((n_per_class, n_features)) * 0.3
    # Set internet + storage flags high
    for i, feat in enumerate(ALL_FEATURES):
        if "INTERNET" in feat or "READ_EXTERNAL" in feat or "WRITE_EXTERNAL" in feat:
            X_adware[:, i] = rng.uniform(0.7, 1.0, n_per_class)
    X_parts.append(X_adware)
    y_parts.extend([0] * n_per_class)

    # Banking Trojan (class 1): SMS + accessibility + overlay
    X_banking = rng.random((n_per_class, n_features)) * 0.2
    for i, feat in enumerate(ALL_FEATURES):
        if any(k in feat for k in ["READ_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW",
                                    "BIND_ACCESSIBILITY", "india_ioc", "dangerous_combo"]):
            X_banking[:, i] = rng.uniform(0.8, 1.0, n_per_class)
        if "yara_critical" in feat or "yara_high" in feat:
            X_banking[:, i] = rng.uniform(0.3, 0.8, n_per_class)
    X_parts.append(X_banking)
    y_parts.extend([1] * n_per_class)

    # SMS Malware (class 2): SMS permissions + send SMS
    X_sms = rng.random((n_per_class, n_features)) * 0.2
    for i, feat in enumerate(ALL_FEATURES):
        if any(k in feat for k in ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "yara_medium"]):
            X_sms[:, i] = rng.uniform(0.7, 1.0, n_per_class)
    X_parts.append(X_sms)
    y_parts.extend([2] * n_per_class)

    # Riskware (class 3): moderate suspicious features
    X_risk = rng.random((n_per_class, n_features)) * 0.4
    for i, feat in enumerate(ALL_FEATURES):
        if any(k in feat for k in ["REQUEST_INSTALL", "dex_classloader", "INTERNET"]):
            X_risk[:, i] = rng.uniform(0.5, 0.9, n_per_class)
    X_parts.append(X_risk)
    y_parts.extend([3] * n_per_class)

    # Benign (class 4): low values across all dangerous features
    X_benign = rng.random((n_per_class, n_features)) * 0.15
    for i, feat in enumerate(ALL_FEATURES):
        if any(k in feat for k in ["INTERNET", "ACCESS_NETWORK", "VIBRATE", "READ_EXTERNAL"]):
            X_benign[:, i] = rng.uniform(0.3, 0.7, n_per_class)
        if any(k in feat for k in ["yara", "india_ioc", "dangerous_combo"]):
            X_benign[:, i] = rng.uniform(0.0, 0.05, n_per_class)
    X_parts.append(X_benign)
    y_parts.extend([4] * n_per_class)

    X = np.clip(np.vstack(X_parts), 0.0, 1.0).astype(np.float32)
    y = np.array(y_parts, dtype=np.int32)

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def load_maldroid_dataset() -> tuple | None:
    """
    Attempt to load real CICMalDroid 2020 CSVs.
    Returns (X, y) or None if dataset not found.
    """
    import pandas as pd

    csv_files = list(DATA_DIR.glob("**/*.csv"))
    if not csv_files:
        return None

    print(f"Found {len(csv_files)} CSV(s) in {DATA_DIR}")
    dfs = []
    for f in csv_files[:5]:  # limit to 5 files
        try:
            df = pd.read_csv(f, low_memory=False)
            dfs.append(df)
            print(f"  Loaded {f.name}: {df.shape}")
        except Exception as e:
            print(f"  Skip {f.name}: {e}")

    if not dfs:
        return None

    data = pd.concat(dfs, ignore_index=True)

    # MalDroid label column is typically 'Label' or 'Class'
    label_col = None
    for col in ["Label", "label", "Class", "class", "Category", "category"]:
        if col in data.columns:
            label_col = col
            break

    if label_col is None:
        print("Could not find label column in dataset.")
        return None

    # Map string labels to integers
    label_map = {"Adware": 0, "Banking": 1, "SMS": 2, "Riskware": 3, "Benign": 4,
                 "ADWARE": 0, "BANKING": 1, "SMS_MALWARE": 2, "RISKWARE": 3, "BENIGN": 4}
    data[label_col] = data[label_col].map(label_map)
    data = data.dropna(subset=[label_col])

    y = data[label_col].astype(int).values
    X = data.drop(columns=[label_col]).select_dtypes(include=[np.number]).fillna(0).values.astype(np.float32)

    # Pad or truncate to expected feature count
    n_expected = len(ALL_FEATURES)
    if X.shape[1] < n_expected:
        pad = np.zeros((X.shape[0], n_expected - X.shape[1]), dtype=np.float32)
        X = np.hstack([X, pad])
    else:
        X = X[:, :n_expected]

    return X, y


def train():
    print("=" * 60)
    print("  DroidRaksha — XGBoost + Isolation Forest Training")
    print("=" * 60)
    print()

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import MinMaxScaler
    import xgboost as xgb
    import joblib

    # ── Load or generate dataset ──────────────────────────────────────────────
    result = load_maldroid_dataset()
    if result is None:
        X, y = generate_synthetic_dataset(n_samples=8000)
    else:
        X, y = result

    print(f"Dataset: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"Classes: {dict(zip(CLASSES, [int((y==i).sum()) for i in range(5)]))}")
    print()

    # ── SMOTE for class balance ───────────────────────────────────────────────
    try:
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(random_state=42)
        X, y = smote.fit_resample(X, y)
        print(f"After SMOTE: {X.shape[0]} samples")
    except ImportError:
        print("imblearn not installed — skipping SMOTE (install: pip install imbalanced-learn)")

    # ── Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Scale ─────────────────────────────────────────────────────────────────
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── Train XGBoost ─────────────────────────────────────────────────────────
    print("Training XGBoost (n_estimators=200, max_depth=6)…")
    t0 = time.time()

    clf = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )
    print(f"XGBoost trained in {time.time() - t0:.1f}s")

    y_pred = clf.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=CLASSES))

    # Save XGBoost model
    xgb_path = MODEL_DIR / "xgboost_maldroid.pkl"
    joblib.dump(clf, xgb_path)
    print(f"\n✅ XGBoost saved → {xgb_path}")

    # Save feature columns
    feat_path = MODEL_DIR / "feature_columns.json"
    with open(feat_path, "w") as f:
        json.dump(ALL_FEATURES, f, indent=2)
    print(f"✅ Feature columns saved → {feat_path}")

    # ── Top feature importances ───────────────────────────────────────────────
    importances = clf.feature_importances_
    top_idx = np.argsort(importances)[::-1][:10]
    print("\nTop 10 Feature Importances:")
    for i, idx in enumerate(top_idx, 1):
        print(f"  {i:2}. {ALL_FEATURES[idx]:<45} {importances[idx]:.4f}")

    # ── Train Isolation Forest ────────────────────────────────────────────────
    print("\nTraining Isolation Forest on benign samples…")
    benign_mask = y_train == 4   # class 4 = Benign
    X_benign    = X_train[benign_mask]

    from sklearn.ensemble import IsolationForest
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.05,  # 5% expected outliers in benign set
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_benign)
    print("Isolation Forest trained.")

    # Evaluate: benign should score > -0.1, malware < -0.1
    X_malware = X_test[y_test != 4]
    X_test_benign = X_test[y_test == 4]

    if len(X_test_benign) > 0 and len(X_malware) > 0:
        benign_scores  = iso.score_samples(X_test_benign)
        malware_scores = iso.score_samples(X_malware)
        print(f"  Benign mean score:  {benign_scores.mean():.4f} (should be > -0.05)")
        print(f"  Malware mean score: {malware_scores.mean():.4f} (should be < -0.05)")
        detected = (malware_scores < -0.05).mean()
        print(f"  Zero-day detection rate: {detected:.1%}")

    iso_path = MODEL_DIR / "isolation_forest.pkl"
    joblib.dump(iso, iso_path)
    print(f"\n✅ Isolation Forest saved → {iso_path}")

    print("\n" + "=" * 60)
    print("  Training complete! Models are ready.")
    print("  Run the DroidRaksha backend to use them.")
    print("=" * 60)


if __name__ == "__main__":
    train()

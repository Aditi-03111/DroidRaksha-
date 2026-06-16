"""
XGBoost Malware Classifier — DroidRaksha P11
=============================================
Implements feature extraction compatible with CICMalDroid 2020 dataset,
XGBoost inference, and SHAP explainability.

Model file: models/xgboost_maldroid.pkl
Feature map: models/feature_columns.json

If no trained model exists, returns a graceful fallback so the rest
of the pipeline continues uninterrupted.
"""
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Optional

import numpy as np
from loguru import logger

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parents[2]
MODEL_PATH  = BASE_DIR / "models" / "xgboost_maldroid.pkl"
FEAT_PATH   = BASE_DIR / "models" / "feature_columns.json"

# ── Lazy-loaded globals ───────────────────────────────────────────────────────
_model   = None
_explainer = None
_feature_columns: Optional[list[str]] = None

# ── MalDroid 2020 class labels ────────────────────────────────────────────────
CLASSES = ["Adware", "Banking", "SMS_Malware", "Riskware", "Benign"]

# ── Known Android permissions (subset of 215 MalDroid features) ───────────────
KNOWN_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    "RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "FOREGROUND_SERVICE",
    "SYSTEM_ALERT_WINDOW", "INJECT_EVENTS",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "BIND_INPUT_METHOD",
    "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_VPN_SERVICE",
    "REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DELETE_PACKAGES",
    "READ_PHONE_STATE", "CALL_PHONE", "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS",
    "GET_TASKS", "REAL_GET_TASKS", "KILL_BACKGROUND_PROCESSES",
    "CHANGE_NETWORK_STATE", "CHANGE_WIFI_STATE",
    "WRITE_SETTINGS", "WRITE_SECURE_SETTINGS", "CHANGE_CONFIGURATION",
    "REBOOT", "MOUNT_UNMOUNT_FILESYSTEMS",
    "READ_LOGS", "DUMP",
    "VIBRATE", "FLASHLIGHT",
    "NFC", "BLUETOOTH", "BLUETOOTH_ADMIN",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
    "SCHEDULE_EXACT_ALARM", "USE_EXACT_ALARM",
    "UPDATE_DEVICE_STATS", "DEVICE_POWER",
    "MASTER_CLEAR", "FACTORY_RESET",
    "SEND_RESPOND_VIA_MESSAGE",
]

# ── Known sensitive API call indicators (from strings / obfuscation) ──────────
SENSITIVE_APIS = [
    "dex_classloader", "reflection", "string_encryption", "native_code",
    "runtime_exec", "getimei", "getsimserialnum", "getdeviceid",
    "getaccounts", "getlastknownlocation", "requestlocationupdates",
    "sendtextmessage", "getinputstream", "httpurlconnection",
    "base64decode", "cipher_init", "secretkeyspec",
    "contentresolver_query", "getreadabledatabase",
    "mediarecorder_start", "camera_open",
]

# ── Intent / receiver features ────────────────────────────────────────────────
INTENT_FEATURES = [
    "has_boot_receiver", "has_sms_receiver", "has_call_receiver",
    "has_admin_receiver", "has_notification_listener",
    "has_accessibility_service", "has_vpn_service",
    "has_foreground_service", "has_device_admin",
]

# ── Full feature list ─────────────────────────────────────────────────────────
ALL_FEATURES = (
    [f"perm_{p}" for p in KNOWN_PERMISSIONS] +
    [f"api_{a}" for a in SENSITIVE_APIS] +
    INTENT_FEATURES +
    [
        "obfuscation_score",
        "dangerous_combo_count",
        "yara_critical_count",
        "yara_high_count",
        "yara_medium_count",
        "yara_low_count",
        "india_ioc_score",
        "url_count",
        "ip_count",
        "suspicious_string_count",
    ]
)


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_maldroid_features(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None = None,
) -> np.ndarray:
    """
    Extract a feature vector compatible with CICMalDroid 2020.
    Returns shape (1, N) for XGBoost predict.
    """
    feat: dict[str, float] = {f: 0.0 for f in ALL_FEATURES}

    # Permissions
    perm_names = {
        p.get("name", "").split(".")[-1].upper()
        for p in manifest.get("permissions", [])
    }
    for p in KNOWN_PERMISSIONS:
        feat[f"perm_{p}"] = 1.0 if p in perm_names else 0.0

    # API call indicators from obfuscation flags
    obf = obfuscation or {}
    feat["api_dex_classloader"]   = 1.0 if obf.get("has_dex_classloader")    else 0.0
    feat["api_reflection"]        = 1.0 if obf.get("has_reflection")          else 0.0
    feat["api_string_encryption"] = 1.0 if obf.get("has_string_encryption")   else 0.0
    feat["api_native_code"]       = 1.0 if obf.get("has_native_code")         else 0.0

    # API hints from suspicious strings
    str_vals = " ".join(
        s.get("value", "").lower()
        for key in ("suspicious_strings", "urls")
        for s in strings.get(key, [])
    )
    feat["api_runtime_exec"]       = 1.0 if "runtime" in str_vals or "exec(" in str_vals else 0.0
    feat["api_getimei"]            = 1.0 if "getimei" in str_vals else 0.0
    feat["api_getsimserialnum"]    = 1.0 if "getsimserial" in str_vals else 0.0
    feat["api_getdeviceid"]        = 1.0 if "getdeviceid" in str_vals else 0.0
    feat["api_getaccounts"]        = 1.0 if "getaccounts" in str_vals else 0.0
    feat["api_sendtextmessage"]    = 1.0 if "sendtextmessage" in str_vals else 0.0
    feat["api_base64decode"]       = 1.0 if "base64" in str_vals else 0.0
    feat["api_cipher_init"]        = 1.0 if "cipher" in str_vals or "aes" in str_vals else 0.0
    feat["api_mediarecorder_start"]= 1.0 if "mediarecorder" in str_vals else 0.0
    feat["api_camera_open"]        = 1.0 if "camera.open" in str_vals else 0.0
    feat["api_httpurlconnection"]  = 1.0 if "httpurlconnection" in str_vals or "okhttp" in str_vals else 0.0
    feat["api_secretkeyspec"]      = 1.0 if "secretkeyspec" in str_vals else 0.0

    # Remaining API features default to 0 (not extractable without dex analysis)

    # Intent / component features
    services   = set(s.lower() for s in manifest.get("services", []))
    receivers  = set(r.lower() for r in manifest.get("receivers", []))
    feat["has_boot_receiver"]          = 1.0 if "RECEIVE_BOOT_COMPLETED" in perm_names else 0.0
    feat["has_sms_receiver"]           = 1.0 if "RECEIVE_SMS" in perm_names else 0.0
    feat["has_call_receiver"]          = 1.0 if "PROCESS_OUTGOING_CALLS" in perm_names else 0.0
    feat["has_admin_receiver"]         = 1.0 if "BIND_DEVICE_ADMIN" in perm_names else 0.0
    feat["has_notification_listener"]  = 1.0 if "BIND_NOTIFICATION_LISTENER_SERVICE" in perm_names else 0.0
    feat["has_accessibility_service"]  = 1.0 if "BIND_ACCESSIBILITY_SERVICE" in perm_names else 0.0
    feat["has_vpn_service"]            = 1.0 if "BIND_VPN_SERVICE" in perm_names else 0.0
    feat["has_foreground_service"]     = 1.0 if "FOREGROUND_SERVICE" in perm_names else 0.0
    feat["has_device_admin"]           = 1.0 if "BIND_DEVICE_ADMIN" in perm_names else 0.0

    # Numeric features
    feat["obfuscation_score"]       = float(obf.get("score", 0)) / 100.0
    feat["dangerous_combo_count"]   = float(len(manifest.get("dangerous_combos", [])))
    yara_matches = yara.get("matches", [])
    feat["yara_critical_count"] = float(sum(1 for m in yara_matches if m.get("severity") == "CRITICAL"))
    feat["yara_high_count"]     = float(sum(1 for m in yara_matches if m.get("severity") == "HIGH"))
    feat["yara_medium_count"]   = float(sum(1 for m in yara_matches if m.get("severity") == "MEDIUM"))
    feat["yara_low_count"]      = float(sum(1 for m in yara_matches if m.get("severity") == "LOW"))

    ioc = india_ioc or {}
    india_score = (
        (20 if ioc.get("is_fake_upi") else 0) +
        (20 if ioc.get("is_fake_bank") else 0) +
        (15 if ioc.get("is_loan_scam") else 0) +
        len(ioc.get("matched_ips", [])) * 5 +
        len(ioc.get("matched_domains", [])) * 5
    )
    feat["india_ioc_score"]          = float(min(100, india_score)) / 100.0
    feat["url_count"]                = float(min(50, len(strings.get("urls", []))))
    feat["ip_count"]                 = float(min(50, len(strings.get("ips", []))))
    feat["suspicious_string_count"]  = float(min(100, len(strings.get("suspicious_strings", []))))

    # Build ordered numpy array
    vector = np.array([[feat[f] for f in ALL_FEATURES]], dtype=np.float32)
    return vector


# ── Model loading ─────────────────────────────────────────────────────────────

def _load_model():
    global _model, _explainer, _feature_columns
    if _model is not None:
        return True

    if not MODEL_PATH.exists():
        logger.warning(f"XGBoost model not found at {MODEL_PATH}. Run scripts/train_xgboost_maldroid.py first.")
        return False

    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("XGBoost model loaded successfully.")

        if FEAT_PATH.exists():
            with open(FEAT_PATH) as f:
                _feature_columns = json.load(f)

        # Build SHAP explainer
        try:
            import shap
            _explainer = shap.TreeExplainer(_model)
            logger.info("SHAP TreeExplainer initialised.")
        except ImportError:
            logger.warning("shap not installed — SHAP explanations disabled.")
        except Exception as e:
            logger.warning(f"SHAP explainer error: {e}")

        return True
    except Exception as e:
        logger.error(f"Failed to load XGBoost model: {e}")
        return False


# ── SHAP explanation ──────────────────────────────────────────────────────────

def _get_shap_explanation(feature_vector: np.ndarray, pred_class_idx: int) -> list[dict]:
    """
    Returns top-5 SHAP features driving the predicted class.
    """
    global _explainer
    if _explainer is None:
        return []

    try:
        import shap
        shap_values = _explainer.shap_values(feature_vector)

        # Newer SHAP + XGBoost returns (n_samples, n_features, n_classes)
        # Older versions return list of (n_samples, n_features) per class
        sv = np.array(shap_values)
        if sv.ndim == 3 and sv.shape[-1] > 1:
            # Shape: (n_samples, n_features, n_classes) → pick class slice
            class_shap = sv[0, :, pred_class_idx]
        elif sv.ndim == 3:
            class_shap = sv[0, :, 0]
        elif sv.ndim == 2:
            class_shap = sv[0]
        else:
            class_shap = sv.flatten()

        # Pair feature names with SHAP values
        pairs = sorted(
            zip(ALL_FEATURES, class_shap),
            key=lambda x: abs(x[1]),
            reverse=True,
        )[:5]

        return [
            {
                "feature": name.replace("perm_", "").replace("api_", "").replace("_", " ").title(),
                "raw_name": name,
                "shap_value": round(float(val), 4),
                "direction": "increases" if val > 0 else "decreases",
            }
            for name, val in pairs
            if abs(val) > 0.001
        ]
    except Exception as e:
        logger.warning(f"SHAP computation failed: {e}")
        return []


# ── Main classify function ────────────────────────────────────────────────────

def classify(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None = None,
) -> dict:
    """
    Run XGBoost classification + SHAP explanation.

    Returns:
        {
          "label": "Banking",
          "probability": 0.91,
          "class_probs": {"Adware": 0.02, "Banking": 0.91, ...},
          "shap_top5": [...],
          "available": True,
          "inference_ms": 14,
        }
    """
    t0 = time.perf_counter()

    if not _load_model():
        return {
            "label": "unavailable",
            "probability": 0.0,
            "class_probs": {c: 0.0 for c in CLASSES},
            "shap_top5": [],
            "available": False,
            "inference_ms": 0,
        }

    try:
        features = extract_maldroid_features(manifest, strings, yara, obfuscation, india_ioc)
        proba    = _model.predict_proba(features)[0]          # shape (n_classes,)
        pred_idx = int(np.argmax(proba))
        label    = CLASSES[pred_idx]

        shap_top5 = _get_shap_explanation(features, pred_idx)
        elapsed   = int((time.perf_counter() - t0) * 1000)

        return {
            "label": label,
            "probability": round(float(proba[pred_idx]), 4),
            "class_probs": {c: round(float(p), 4) for c, p in zip(CLASSES, proba)},
            "shap_top5": shap_top5,
            "available": True,
            "inference_ms": elapsed,
        }

    except Exception as e:
        logger.error(f"XGBoost classify failed: {e}")
        return {
            "label": "error",
            "probability": 0.0,
            "class_probs": {c: 0.0 for c in CLASSES},
            "shap_top5": [],
            "available": False,
            "inference_ms": 0,
        }

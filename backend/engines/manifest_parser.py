"""
AndroidManifest.xml parser using androguard.
Extracts package metadata, permissions, and flags dangerous combos.
"""
from __future__ import annotations
import traceback
from loguru import logger

# Dangerous permissions that grant broad access
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.RECEIVE_SMS": "Receive incoming SMS",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.READ_CONTACTS": "Access contact list",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.RECORD_AUDIO": "Microphone access",
    "android.permission.CAMERA": "Camera access",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.PROCESS_OUTGOING_CALLS": "Intercept calls",
    "android.permission.READ_PHONE_STATE": "Device/call info",
    "android.permission.CALL_PHONE": "Make phone calls",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write to storage",
    "android.permission.READ_EXTERNAL_STORAGE": "Read from storage",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Auto-start on boot",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service (keylogger risk)",
    "android.permission.BIND_DEVICE_ADMIN": "Device admin rights",
    "android.permission.CHANGE_NETWORK_STATE": "Modify network",
    "android.permission.INTERNET": "Internet access",
    "android.permission.FOREGROUND_SERVICE": "Background service",
}

# Combinations that strongly indicate malware behavior
DANGEROUS_COMBOS = [
    {
        "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "label": "SMS Exfiltration",
        "severity": "CRITICAL",
    },
    {
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET",
        ],
        "label": "Accessibility Keylogger / Overlay Attack",
        "severity": "CRITICAL",
    },
    {
        "permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.INTERNET",
        ],
        "label": "Remote Device Takeover",
        "severity": "CRITICAL",
    },
    {
        "permissions": [
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        ],
        "label": "Remote Audio Surveillance",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ],
        "label": "Remote Camera Surveillance",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ],
        "label": "GPS Location Tracking",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ],
        "label": "Contact Harvesting",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        ],
        "label": "Persistent Background C2",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ],
        "label": "Overlay Phishing Attack",
        "severity": "HIGH",
    },
    {
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
        ],
        "label": "OTP Interception (Banking Trojan)",
        "severity": "CRITICAL",
    },
]


def analyze(apk_path: str) -> dict:
    """Parse AndroidManifest.xml and return structured analysis."""
    result = {
        "package_name": "unknown",
        "version_name": "unknown",
        "version_code": "0",
        "min_sdk": "unknown",
        "target_sdk": "unknown",
        "permissions": [],
        "dangerous_combos": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "error": None,
    }

    try:
        from androguard.misc import AnalyzeAPK

        a, d, dx = AnalyzeAPK(apk_path)

        result["package_name"] = a.get_package() or "unknown"
        result["version_name"] = a.get_androidversion_name() or "unknown"
        result["version_code"] = str(a.get_androidversion_code() or "0")
        result["min_sdk"] = str(a.get_min_sdk_version() or "unknown")
        result["target_sdk"] = str(a.get_target_sdk_version() or "unknown")

        # Permissions
        declared_perms = set(a.get_permissions())
        for perm in declared_perms:
            is_dangerous = perm in DANGEROUS_PERMISSIONS
            result["permissions"].append({
                "name": perm,
                "is_dangerous": is_dangerous,
                "description": DANGEROUS_PERMISSIONS.get(perm, ""),
            })

        # Dangerous combos
        for combo in DANGEROUS_COMBOS:
            if all(p in declared_perms for p in combo["permissions"]):
                result["dangerous_combos"].append(combo)

        # Components
        result["activities"] = list(a.get_activities() or [])
        result["services"] = list(a.get_services() or [])
        result["receivers"] = list(a.get_receivers() or [])
        result["providers"] = list(a.get_providers() or [])

    except Exception as e:
        logger.warning(f"Androguard failed ({e}), falling back to aapt...")
        try:
            import subprocess
            import re
            proc = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                out = proc.stdout
                pkg_match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", out)
                if pkg_match:
                    result["package_name"] = pkg_match.group(1)
                    result["version_code"] = pkg_match.group(2)
                    result["version_name"] = pkg_match.group(3)
                sdk_match = re.search(r"sdkVersion:'([^']+)'", out)
                if sdk_match: result["min_sdk"] = sdk_match.group(1)
                target_match = re.search(r"targetSdkVersion:'([^']+)'", out)
                if target_match: result["target_sdk"] = target_match.group(1)
                
                perms = set(re.findall(r"uses-permission: name='([^']+)'", out))
                for perm in perms:
                    is_dangerous = perm in DANGEROUS_PERMISSIONS
                    result["permissions"].append({
                        "name": perm,
                        "is_dangerous": is_dangerous,
                        "description": DANGEROUS_PERMISSIONS.get(perm, ""),
                    })
                for combo in DANGEROUS_COMBOS:
                    if all(p in perms for p in combo["permissions"]):
                        result["dangerous_combos"].append(combo)
                logger.info("Successfully parsed manifest using aapt.")
                return result
        except Exception as aapt_e:
            logger.warning(f"aapt fallback failed: {aapt_e}. Falling back to apktool...")

        try:
            import subprocess
            import tempfile
            import os
            from xml.etree import ElementTree as ET
            with tempfile.TemporaryDirectory() as tmpdir:
                subprocess.run(["apktool", "d", "--no-src", "-f", "-o", tmpdir, apk_path], capture_output=True, timeout=60)
                manifest_path = os.path.join(tmpdir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    tree = ET.parse(manifest_path)
                    root = tree.getroot()
                    result["package_name"] = root.get("package", "unknown")
                    ns = {"android": "http://schemas.android.com/apk/res/android"}
                    result["version_code"] = root.get(f"{{{ns['android']}}}versionCode", "0")
                    result["version_name"] = root.get(f"{{{ns['android']}}}versionName", "unknown")
                    
                    uses_sdk = root.find("uses-sdk")
                    if uses_sdk is not None:
                        result["min_sdk"] = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion", "unknown")
                        result["target_sdk"] = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion", "unknown")
                    
                    perms = set()
                    for perm_node in root.findall("uses-permission"):
                        p = perm_node.get(f"{{{ns['android']}}}name")
                        if p: perms.add(p)
                    for perm in perms:
                        is_dangerous = perm in DANGEROUS_PERMISSIONS
                        result["permissions"].append({
                            "name": perm,
                            "is_dangerous": is_dangerous,
                            "description": DANGEROUS_PERMISSIONS.get(perm, ""),
                        })
                    for combo in DANGEROUS_COMBOS:
                        if all(p in perms for p in combo["permissions"]):
                            result["dangerous_combos"].append(combo)
                    logger.info("Successfully parsed manifest using apktool.")
                    return result
        except Exception as apktool_e:
            logger.warning(f"apktool fallback failed: {apktool_e}")

        logger.error(f"All manifest parsers failed. Returning mock data. Original error: {e}")
        result = _mock_manifest(apk_path)
        result["error"] = "All manifest parsing tools (androguard, aapt, apktool) failed."

    return result


def _mock_manifest(apk_path: str) -> dict:
    """Return demo data when androguard is unavailable."""
    import os
    fname = os.path.basename(apk_path)
    return {
        "package_name": f"com.demo.{fname.replace('.apk','').lower()[:20]}",
        "version_name": "2.1.0",
        "version_code": "210",
        "min_sdk": "21",
        "target_sdk": "33",
        "permissions": [
            {"name": "android.permission.READ_SMS", "is_dangerous": True,
             "description": "Read SMS messages"},
            {"name": "android.permission.RECEIVE_SMS", "is_dangerous": True,
             "description": "Receive incoming SMS"},
            {"name": "android.permission.INTERNET", "is_dangerous": False,
             "description": "Internet access"},
            {"name": "android.permission.ACCESS_FINE_LOCATION", "is_dangerous": True,
             "description": "Precise GPS location"},
            {"name": "android.permission.RECORD_AUDIO", "is_dangerous": True,
             "description": "Microphone access"},
            {"name": "android.permission.BIND_ACCESSIBILITY_SERVICE", "is_dangerous": True,
             "description": "Accessibility service (keylogger risk)"},
            {"name": "android.permission.RECEIVE_BOOT_COMPLETED", "is_dangerous": True,
             "description": "Auto-start on boot"},
            {"name": "android.permission.SYSTEM_ALERT_WINDOW", "is_dangerous": True,
             "description": "Draw over other apps"},
        ],
        "dangerous_combos": [
            {"permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
             "label": "SMS Exfiltration", "severity": "CRITICAL"},
            {"permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                             "android.permission.INTERNET"],
             "label": "OTP Interception (Banking Trojan)", "severity": "CRITICAL"},
            {"permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE",
                             "android.permission.INTERNET"],
             "label": "Accessibility Keylogger / Overlay Attack", "severity": "CRITICAL"},
        ],
        "activities": [
            "com.demo.app.MainActivity",
            "com.demo.app.PhishActivity",
            "com.demo.app.OverlayService",
        ],
        "services": [
            "com.demo.app.SmsInterceptService",
            "com.demo.app.C2BackgroundService",
        ],
        "receivers": [
            "com.demo.app.BootReceiver",
            "com.demo.app.SmsReceiver",
        ],
        "providers": [],
        "error": None,
    }

/**
 * DroidRaksha — Frida Offline Hook Script
 * 
 * Run against decompiled smali in headless mode.
 * Extracts API call graphs, crypto usage, and suspicious patterns.
 * 
 * Note: In offline mode this script is parsed for its hook definitions
 * and the patterns are matched against smali bytecode by the Python analyzer.
 */

// ── API Hooks Definition ───────────────────────────────────────────────────

const HOOK_TARGETS = {
  // Telephony / SMS
  "android.telephony.SmsManager": ["sendTextMessage", "sendMultipartTextMessage"],
  "android.telephony.TelephonyManager": ["getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"],

  // Location
  "android.location.LocationManager": ["getLastKnownLocation", "requestLocationUpdates"],

  // Camera / Microphone
  "android.media.MediaRecorder": ["setAudioSource", "start"],
  "android.hardware.Camera": ["takePicture", "open"],

  // Crypto
  "javax.crypto.Cipher": ["getInstance", "init", "doFinal"],
  "javax.crypto.KeyGenerator": ["getInstance", "generateKey"],
  "java.security.MessageDigest": ["getInstance", "digest"],

  // Network
  "java.net.URL": ["openConnection"],
  "java.net.Socket": ["connect"],
  "javax.net.ssl.HttpsURLConnection": ["connect", "getInputStream"],

  // Reflection
  "java.lang.Class": ["forName", "getDeclaredMethod", "getMethod"],
  "java.lang.reflect.Method": ["invoke"],

  // Runtime
  "java.lang.Runtime": ["exec"],
  "android.app.ActivityManager": ["getRunningAppProcesses"],

  // Clipboard
  "android.content.ClipboardManager": ["getPrimaryClip", "setPrimaryClip"],

  // Device Policy
  "android.app.admin.DevicePolicyManager": ["lockNow", "wipeData", "resetPassword"],
};

// ── Anti-Analysis Detectors ─────────────────────────────────────────────────

const ANTI_ANALYSIS = {
  emulator: [
    "ro.kernel.qemu",
    "generic",
    "goldfish",
    "vbox",
    "Build.FINGERPRINT",
    "BUILD.MODEL",
  ],
  root: [
    "/system/xbin/su",
    "/sbin/su",
    "/system/bin/su",
    "which su",
  ],
  debugger: [
    "android.os.Debug.isDebuggerConnected",
    "Debug.waitForDebugger",
  ],
  frida: [
    "frida-agent",
    "libfrida",
    "gum-js-loop",
  ],
};

// Export for Python parser
if (typeof module !== "undefined") {
  module.exports = { HOOK_TARGETS, ANTI_ANALYSIS };
}

"""
Risk scorer: aggregates results from all engines into a 0-100 risk score.
"""
from __future__ import annotations


SEVERITY_SCORES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "SAFE"),
]


def calculate(
    manifest: dict,
    strings: dict,
    cert: dict,
    yara: dict,
    obfuscation: dict,
    virustotal: dict,
    abuseipdb: dict,
    india_ioc: dict,
) -> dict:
    """Calculate overall risk score and return breakdown."""
    breakdown = {
        "permissions": 0,
        "yara": 0,
        "certificate": 0,
        "threat_intel": 0,
        "obfuscation": 0,
        "india_ioc": 0,
        "strings": 0,
    }

    # ── Permissions ──────────────────────────────────────────
    dangerous_count = sum(
        1 for p in manifest.get("permissions", []) if p.get("is_dangerous")
    )
    combo_count = len(manifest.get("dangerous_combos", []))
    breakdown["permissions"] = min(25, dangerous_count * 2 + combo_count * 5)

    # ── YARA ──────────────────────────────────────────────────
    yara_score = 0
    for hit in yara.get("matches", []):
        yara_score += SEVERITY_SCORES.get(hit.get("severity", "MEDIUM"), 8)
    breakdown["yara"] = min(30, yara_score)

    # ── Certificate ───────────────────────────────────────────
    cert_score = 0
    if cert.get("is_self_signed"):
        cert_score += 8
    if cert.get("is_expired"):
        cert_score += 7
    if len(cert.get("warnings", [])) > 2:
        cert_score += 5
    breakdown["certificate"] = min(15, cert_score)

    # ── Threat Intel ──────────────────────────────────────────
    ti_score = 0
    vt = virustotal
    if vt.get("found") and vt.get("detection_count", 0) > 0:
        ratio = vt["detection_count"] / max(vt["total_engines"], 1)
        ti_score += min(20, int(ratio * 30))
    if abuseipdb.get("max_confidence", 0) > 50:
        ti_score += 10
    breakdown["threat_intel"] = min(25, ti_score)

    # ── Obfuscation ───────────────────────────────────────────
    breakdown["obfuscation"] = min(15, int(obfuscation.get("score", 0) * 0.15))

    # ── India IOC ─────────────────────────────────────────────
    ioc_score = 0
    if india_ioc.get("is_fake_upi"):
        ioc_score += 15
    if india_ioc.get("is_fake_bank"):
        ioc_score += 15
    if india_ioc.get("is_loan_scam"):
        ioc_score += 10
    ioc_score += len(india_ioc.get("matched_ips", [])) * 5
    ioc_score += len(india_ioc.get("matched_domains", [])) * 5
    breakdown["india_ioc"] = min(20, ioc_score)

    # ── Strings ───────────────────────────────────────────────
    string_score = 0
    string_score += len(strings.get("ips", [])) * 2
    string_score += len([u for u in strings.get("urls", []) if u.get("risk") == "high"]) * 3
    string_score += len(strings.get("suspicious_strings", [])) * 2
    breakdown["strings"] = min(15, string_score)

    # ── Total ─────────────────────────────────────────────────
    total = sum(breakdown.values())
    total = min(100, total)

    # Map to risk level
    risk_level = "SAFE"
    for threshold, level in RISK_LEVELS:
        if total >= threshold:
            risk_level = level
            break

    # Threat categories
    categories = []
    if india_ioc.get("is_fake_upi") or india_ioc.get("is_fake_bank"):
        categories.append("Banking Trojan")
    if india_ioc.get("is_loan_scam"):
        categories.append("Loan Scam")
    if any("OTP" in h.get("rule", "") or "SMS" in h.get("rule", "") for h in yara.get("matches", [])):
        categories.append("OTP Interceptor")
    if any("Overlay" in h.get("rule", "") or "overlay" in h.get("tags", []) for h in yara.get("matches", [])):
        categories.append("Overlay Attack")
    if obfuscation.get("has_dex_classloader"):
        categories.append("Dropper/Loader")
    if abuseipdb.get("flagged_ips"):
        categories.append("C2 Communication")
    if virustotal.get("malware_families"):
        categories += virustotal["malware_families"][:2]

    return {
        "score": total,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "threat_categories": list(dict.fromkeys(categories)),
    }

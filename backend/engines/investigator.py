import re
import subprocess
import os
from typing import List, Dict

LOGGER = None  # placeholder – you can replace with your logger if desired


def _run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    """Run a command and return CompletedProcess. Captures stdout/stderr, raises on error."""
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def extract_signer_info(apk_path: str) -> Dict[str, str]:
    """Use `apksigner verify --print-certs` to get signing certificate info.
    Returns a dict with keys: subject, issuer, sha256_fingerprint, signing_scheme.
    """
    result = _run_cmd(["apksigner", "verify", "--print-certs", apk_path])
    info = {}
    if result.returncode == 0:
        # Example output lines:
        # Signer #1 certificate SHA-256 digest: <hash>
        # Subject: CN=Example, O=Company, C=US
        # Issuer: CN=Example CA, O=CA Org, C=US
        # Signing scheme: v2
        for line in result.stdout.splitlines():
            line = line.strip()
            if "certificate SHA-256 digest" in line:
                info["sha256_fingerprint"] = line.split(":", 1)[1].strip()
            elif line.startswith("Subject:"):
                info["subject"] = line.split(":", 1)[1].strip()
            elif line.startswith("Issuer:"):
                info["issuer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signing scheme:"):
                info["signing_scheme"] = line.split(":", 1)[1].strip()
    else:
        info["error"] = result.stderr.strip() or "apksigner failed"
    return info


def infer_hosting_source(strings: Dict) -> str:
    """Look for a Google Play Store URL in the extracted strings.
    Returns the URL if found, otherwise empty string.
    """
    for entry in strings.get("urls", []):
        url = entry.get("value", "")
        if "play.google.com/store/apps/details" in url:
            return url
    return ""


def static_endpoint_extraction(strings: Dict) -> List[Dict[str, any]]:
    """Collect endpoints and attach guidance where applicable.

    Returns a list of dicts; each dict now contains:
    - type: "url" or "ip"
    - value: the endpoint string
    - evidence: "strings"
    - guidance: optional list of recommended next steps
    """
    """Collect all URLs and IPs found in the static string extraction step.
    Returns a list of dicts: {type: "url"|"ip", value: <the value>, evidence: "strings"}
    """
    endpoints = []
    for entry in strings.get("urls", []):
        val = entry.get("value")
        if val:
            endpoint = {"type": "url", "value": val, "evidence": "strings"}
            # Detect potential database URLs (simple heuristic)
            if any(keyword in val.lower() for keyword in ["db", "database", ".sql", ".php", ".aspx", ".cgi"]):
                endpoint["guidance"] = [
                    "Perform WHOIS lookup",
                    "Preserve the URL as evidence",
                    "Check passive DNS history",
                    "Correlate with known threat intelligence"
                ]
            endpoints.append(endpoint)

    for entry in strings.get("ips", []):
        val = entry.get("value")
        if val:
            endpoints.append({"type": "ip", "value": val, "evidence": "strings"})
    return endpoints


def build_evidence_report(creator_info: Dict, hosting_url: str, contacts: List[Dict]) -> Dict:
    """Create a structured evidence block linking each finding to its source.
    Simple implementation – just bundles the inputs.
    """
    return {
        "creator": creator_info,
        "hosting": hosting_url,
        "contacts": contacts,
        "guidance": {
            # Top‑level guidance could be added later if needed
        },
    }


def analyze(apk_path: str, manifest: Dict, strings: Dict) -> Dict:
    """High‑level wrapper used by the Celery task.
    Returns a dict with keys: creator, hosting, contacts, evidence.
    """
    creator = extract_signer_info(apk_path)
    hosting = infer_hosting_source(strings)
    contacts = static_endpoint_extraction(strings)
    evidence = build_evidence_report(creator, hosting, contacts)
    return evidence

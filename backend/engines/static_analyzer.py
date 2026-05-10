"""
Static analysis orchestrator: runs all engines and assembles the final result.
"""
from __future__ import annotations
import hashlib
import os
import uuid
from datetime import datetime, timezone
from loguru import logger

from backend.engines import (
    manifest_parser,
    string_extractor,
    cert_analyzer,
    yara_scanner,
    obfuscation,
)
from backend.intel import india_ioc, virustotal, abuseipdb
from backend.scoring import risk_scorer
from backend.ai import narrative as ai_narrative_module


def _hash_file(path: str) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size": os.path.getsize(path),
    }


async def run(apk_path: str, filename: str) -> dict:
    """Run all analysis engines and return a complete analysis result."""
    logger.info(f"Starting analysis: {filename}")

    analysis_id = str(uuid.uuid4())
    hashes = _hash_file(apk_path)

    logger.info("Running manifest parser...")
    manifest = manifest_parser.analyze(apk_path)

    logger.info("Running string extractor...")
    strings = string_extractor.analyze(apk_path)

    logger.info("Running certificate analyzer...")
    cert = cert_analyzer.analyze(apk_path)

    logger.info("Running YARA scanner...")
    yara = yara_scanner.analyze(apk_path)

    logger.info("Running obfuscation detector...")
    obf = obfuscation.analyze(apk_path)

    logger.info("Running India IOC check...")
    ioc = india_ioc.analyze(apk_path, manifest, strings)

    logger.info("Running VirusTotal lookup...")
    vt = await virustotal.analyze(apk_path)

    logger.info("Running AbuseIPDB check...")
    ip_list = [item["value"] for item in strings.get("ips", [])]
    abuse = await abuseipdb.analyze(ip_list)

    logger.info("Calculating risk score...")
    risk = risk_scorer.calculate(manifest, strings, cert, yara, obf, vt, abuse, ioc)

    logger.info("Getting MITRE ATT&CK mapping...")
    mitre = ai_narrative_module.get_mitre_tactics(manifest, obf, yara)

    logger.info("Generating AI narrative...")
    ai_text, recommendations = await ai_narrative_module.generate_narrative(
        manifest, risk, yara, ioc, cert, obf
    )

    result = {
        "id": analysis_id,
        "status": "complete",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hashes": hashes,
        "filename": filename,
        "manifest": manifest,
        "strings": strings,
        "certificate": cert,
        "yara": yara,
        "obfuscation": obf,
        "virustotal": vt,
        "abuseipdb": abuse,
        "india_ioc": ioc,
        "risk": risk,
        "mitre": mitre,
        "ai_narrative": ai_text,
        "ai_recommendations": recommendations,
    }

    logger.info(f"Analysis complete: {analysis_id} | Risk: {risk['risk_level']} ({risk['score']}/100)")
    return result

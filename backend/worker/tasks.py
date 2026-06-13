"""
Celery tasks — run_analysis_task runs the full static analysis pipeline
and publishes granular progress events to Redis Pub/Sub so the WebSocket
endpoint can stream them to the browser in real time.

Progress events format (JSON published to channel "progress:{job_id}"):
  {"stage": "manifest",  "pct": 15, "msg": "Parsing AndroidManifest.xml..."}
  {"stage": "complete",  "pct": 100, "analysis_id": "<uuid>"}
  {"stage": "error",     "pct": 0,   "msg": "Analysis failed: ..."}
"""
from __future__ import annotations
import asyncio
import json
import os
import hashlib

import redis as sync_redis

from backend.worker.celery_app import celery_app

# Synchronous Redis client for Pub/Sub (Celery tasks are sync)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis = sync_redis.from_url(REDIS_URL, decode_responses=True)


def _publish(job_id: str, payload: dict) -> None:
    """Publish a progress event to the job's Redis channel."""
    _redis.publish(f"progress:{job_id}", json.dumps(payload))


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="backend.worker.tasks.run_analysis_task",
    max_retries=2,
    soft_time_limit=600,
    time_limit=720,
)
def run_analysis_task(self, apk_path: str, filename: str, job_id: str) -> dict:
    """
    Full static analysis pipeline as a Celery task.
    Publishes granular progress (0–100%) to Redis channel 'progress:{job_id}'.
    """
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
    from backend.db import database

    try:
        # ── Stage 1: Hashing (5%) ─────────────────────────────────────────
        _publish(job_id, {"stage": "hashing", "pct": 5, "msg": "Computing file hashes..."})
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        hashes = {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "file_size": os.path.getsize(apk_path),
        }

        # ── Stage 2: Manifest (20%) ───────────────────────────────────────
        _publish(job_id, {"stage": "manifest", "pct": 20, "msg": "Parsing AndroidManifest.xml..."})
        manifest = manifest_parser.analyze(apk_path)

        # ── Stage 3: Strings (35%) ────────────────────────────────────────
        _publish(job_id, {"stage": "strings", "pct": 35, "msg": "Extracting strings & IOCs..."})
        strings = string_extractor.analyze(apk_path)

        # ── Stage 4: Certificate (45%) ────────────────────────────────────
        _publish(job_id, {"stage": "certificate", "pct": 45, "msg": "Analysing signing certificate..."})
        cert = cert_analyzer.analyze(apk_path)

        # ── Stage 5: YARA (58%) ───────────────────────────────────────────
        _publish(job_id, {"stage": "yara", "pct": 58, "msg": "Running 50 YARA rules..."})
        yara = yara_scanner.analyze(apk_path)

        # ── Stage 6: Obfuscation (65%) ────────────────────────────────────
        _publish(job_id, {"stage": "obfuscation", "pct": 65, "msg": "Detecting obfuscation & packers..."})
        obf = obfuscation.analyze(apk_path)

        # ── Stage 7: India IOC (72%) ──────────────────────────────────────
        _publish(job_id, {"stage": "india_ioc", "pct": 72, "msg": "Checking India threat intelligence..."})
        ioc = india_ioc.analyze(apk_path, manifest, strings)

        # ── Stage 8: Threat Intel (80%) ───────────────────────────────────
        _publish(job_id, {"stage": "threat_intel", "pct": 80, "msg": "Querying VirusTotal & AbuseIPDB..."})
        vt = _run_async(virustotal.analyze(apk_path))
        ip_list = [item["value"] for item in strings.get("ips", [])]
        abuse = _run_async(abuseipdb.analyze(ip_list))

        # ── Stage 9: Risk Score (87%) ─────────────────────────────────────
        _publish(job_id, {"stage": "risk_score", "pct": 87, "msg": "Calculating risk score..."})
        risk = risk_scorer.calculate(manifest, strings, cert, yara, obf, vt, abuse, ioc)

        # ── Stage 10: MITRE ATT&CK (92%) ─────────────────────────────────
        _publish(job_id, {"stage": "mitre", "pct": 92, "msg": "Mapping MITRE ATT&CK techniques..."})
        mitre = ai_narrative_module.get_mitre_tactics(manifest, obf, yara)

        # ── Stage 11: AI Narrative (97%) ─────────────────────────────────
        _publish(job_id, {"stage": "ai", "pct": 97, "msg": "Generating AI threat narrative..."})
        ai_text, recommendations = _run_async(
            ai_narrative_module.generate_narrative(manifest, risk, yara, ioc, cert, obf)
        )

        import uuid
        from datetime import datetime, timezone
        analysis_id = str(uuid.uuid4())
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

        # ── Save to DB (99%) ──────────────────────────────────────────────
        _publish(job_id, {"stage": "saving", "pct": 99, "msg": "Saving results to database..."})
        _run_async(database.save_analysis(result))

        # ── Done (100%) ───────────────────────────────────────────────────
        _publish(job_id, {
            "stage": "complete",
            "pct": 100,
            "msg": f"Analysis complete — {risk['risk_level']} ({risk['score']}/100)",
            "analysis_id": analysis_id,
            "risk_level": risk["risk_level"],
            "risk_score": risk["score"],
        })
        return result

    except Exception as exc:
        _publish(job_id, {"stage": "error", "pct": 0, "msg": f"Analysis failed: {str(exc)}"})
        raise self.retry(exc=exc, countdown=5)

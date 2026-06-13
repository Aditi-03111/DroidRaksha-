"""
Upload route — accepts APK, validates, then submits async Celery job.
Returns {job_id, status: "queued"} immediately so the UI can connect
to the WebSocket for real-time progress.

Cache hit (same SHA256 seen before) → returns full result instantly
without re-queuing since the file was already analysed.
"""
from __future__ import annotations
import hashlib
import os
import uuid

from fastapi import APIRouter, HTTPException, UploadFile, File
from loguru import logger

from backend.db import database

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_FILE_SIZE = 700 * 1024 * 1024  # 700 MB
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _is_apk(filename: str, data: bytes) -> bool:
    return filename.lower().endswith(".apk") and data[:2] == b"PK"


@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    """
    Upload an APK. Returns immediately with a job_id and WebSocket URL.
    Frontend connects to /api/ws/{job_id} for live progress.
    On cache hit, returns the existing result directly.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    data = await file.read()

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 700MB)")

    if not _is_apk(file.filename, data):
        raise HTTPException(status_code=400, detail="Invalid file — only .apk files accepted")

    # Compute SHA256 for deduplication
    sha256 = hashlib.sha256(data).hexdigest()

    # ── Cache hit ────────────────────────────────────────────────────────────
    cached = await database.get_analysis_by_hash(sha256)
    if cached:
        logger.info(f"Cache hit for {sha256[:16]}...")
        # Ensure APK is still on disk (needed for file tree / manifest)
        apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
        if not os.path.exists(apk_path):
            with open(apk_path, "wb") as f_out:
                f_out.write(data)
        # Return cached result with a sentinel job_id so the UI skips progress
        return {
            "job_id": "cached",
            "status": "complete",
            "cached": True,
            "result": cached,
        }

    # ── Save APK persistently ────────────────────────────────────────────────
    apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
    if not os.path.exists(apk_path):
        with open(apk_path, "wb") as f_out:
            f_out.write(data)
        logger.info(f"Saved APK → {apk_path}")

    # ── Submit Celery task ───────────────────────────────────────────────────
    job_id = str(uuid.uuid4())
    try:
        from backend.worker.tasks import run_analysis_task
        run_analysis_task.apply_async(
            args=[apk_path, file.filename, job_id],
            task_id=job_id,
            queue="analysis",
        )
        logger.info(f"Queued analysis job {job_id[:8]}... for {file.filename}")
    except Exception as e:
        # Celery/Redis unavailable — fall back to synchronous analysis
        logger.warning(f"Celery unavailable ({e}), falling back to sync analysis")
        from backend.engines import static_analyzer
        result = await static_analyzer.run(apk_path, file.filename)
        await database.save_analysis(result)
        return {
            "job_id": "sync",
            "status": "complete",
            "cached": False,
            "result": result,
        }

    return {
        "job_id": job_id,
        "status": "queued",
        "cached": False,
        "ws_url": f"/api/ws/{job_id}",
    }

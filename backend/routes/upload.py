"""
Upload route: accepts APK, validates, runs analysis, persists result.
"""
from __future__ import annotations
import os
import shutil
import tempfile
import hashlib
from fastapi import APIRouter, UploadFile, File, HTTPException
from loguru import logger

from backend.engines import static_analyzer
from backend.db import database

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_FILE_SIZE = 700 * 1024 * 1024  # 700MB
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _is_apk(filename: str, data: bytes) -> bool:
    """Validate that file is an APK (ZIP magic bytes)."""
    return filename.lower().endswith(".apk") and data[:2] == b"PK"


@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    """
    Upload an APK file and run full static analysis.
    Returns the complete analysis result immediately.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Read file
    data = await file.read()

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 700MB)")

    if not _is_apk(file.filename, data):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .apk files are accepted.",
        )

    # Check cache by SHA256
    sha256 = hashlib.sha256(data).hexdigest()
    cached = await database.get_analysis_by_hash(sha256)
    if cached:
        logger.info(f"Cache hit for {sha256[:16]}...")
        return cached

    # Write to temp file
    with tempfile.NamedTemporaryFile(
        suffix=".apk", dir=UPLOAD_DIR, delete=False
    ) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        result = await static_analyzer.run(tmp_path, file.filename)
        await database.save_analysis(result)
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

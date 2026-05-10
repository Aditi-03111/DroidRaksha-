"""
Report route: returns shareable public report by SHA256 or analysis ID.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from backend.db import database

router = APIRouter()


@router.get("/report/{identifier}")
async def get_report(identifier: str):
    """
    Get a public report by analysis ID or SHA256 hash.
    Used for shareable links: /report/<id> or /report/<sha256>
    """
    # Try by analysis ID first
    result = await database.get_analysis(identifier)
    if result:
        return result

    # Try by SHA256
    result = await database.get_analysis_by_hash(identifier)
    if result:
        return result

    raise HTTPException(status_code=404, detail="Report not found")

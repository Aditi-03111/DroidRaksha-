"""
Analysis retrieval routes.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from backend.db import database

router = APIRouter()


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get a completed analysis result by ID."""
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result

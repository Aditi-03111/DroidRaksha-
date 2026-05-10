"""
Stats route: returns dashboard statistics.
"""
from __future__ import annotations
from fastapi import APIRouter
from backend.db import database

router = APIRouter()


@router.get("/stats")
async def get_stats():
    """Return aggregated statistics for the dashboard."""
    return await database.get_stats()

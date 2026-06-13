"""
DroidRaksha — FastAPI Backend Entry Point
"""
from __future__ import annotations
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from loguru import logger

from backend.db.database import init_db
from backend.routes import upload, analysis, report, stats, websocket

load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DroidRaksha backend starting up...")
    await init_db()
    yield
    logger.info("DroidRaksha backend shutting down...")


app = FastAPI(
    title="DroidRaksha API",
    description="India's AI-powered APK Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "http://localhost:3000",
        "http://localhost:3001",
        "https://droid-raksha.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes — all under /api prefix
app.include_router(upload.router, prefix="/api", tags=["Analysis"])
app.include_router(analysis.router, prefix="/api", tags=["Analysis"])
app.include_router(report.router, prefix="/api", tags=["Reports"])
app.include_router(stats.router, prefix="/api", tags=["Dashboard"])
app.include_router(websocket.router, prefix="/api", tags=["WebSocket"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "DroidRaksha API v1.0"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("BACKEND_PORT", "8000"))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)

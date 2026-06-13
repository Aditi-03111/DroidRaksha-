"""
WebSocket progress endpoint — streams real-time analysis progress to the browser.

Flow:
  1. Browser connects to ws://localhost:8000/api/ws/{job_id}
  2. Server subscribes to Redis Pub/Sub channel "progress:{job_id}"
  3. Every progress event is forwarded as JSON to the WebSocket client
  4. Connection closes when stage == "complete" or "error"
"""
from __future__ import annotations
import asyncio
import json
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger
import redis.asyncio as aioredis

router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@router.websocket("/ws/{job_id}")
async def analysis_progress_ws(websocket: WebSocket, job_id: str):
    """
    Subscribe to Redis channel progress:{job_id} and stream events to browser.
    Closes automatically when analysis finishes or errors.
    """
    await websocket.accept()
    logger.info(f"WS connected for job {job_id[:8]}...")

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe(f"progress:{job_id}")

    try:
        # Send immediate "connected" ack so the UI doesn't show a blank state
        await websocket.send_json({
            "stage": "queued",
            "pct": 0,
            "msg": "Analysis queued — waiting for worker...",
        })

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                event = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue

            # Forward event to browser
            await websocket.send_json(event)

            # Close connection when done
            if event.get("stage") in ("complete", "error"):
                break

    except WebSocketDisconnect:
        logger.info(f"WS disconnected for job {job_id[:8]}")
    except Exception as e:
        logger.error(f"WS error for job {job_id[:8]}: {e}")
        try:
            await websocket.send_json({"stage": "error", "pct": 0, "msg": str(e)})
        except Exception:
            pass
    finally:
        await pubsub.unsubscribe(f"progress:{job_id}")
        await redis.aclose()
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info(f"WS closed for job {job_id[:8]}")

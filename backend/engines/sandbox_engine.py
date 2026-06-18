"""
Sandbox Engine — Docker orchestrator for DroidRaksha APK Sandbox.

Responsibilities:
  1. Check if Docker daemon is reachable (graceful fallback if not)
  2. Build/pull the sandbox image (once)
  3. Spin up a container per APK, mount input/output dirs
  4. Stream container logs for real-time progress
  5. Parse /output/result.json and return structured dict

If Docker is unavailable → returns {"sandbox_available": False, "error": "..."}
so the rest of the pipeline is unaffected.
"""
from __future__ import annotations
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

from loguru import logger

# ── Config ─────────────────────────────────────────────────────────────────────
SANDBOX_IMAGE   = os.getenv("SANDBOX_IMAGE", "droidraksha-sandbox:latest")
SANDBOX_DIR     = Path(__file__).parent.parent.parent / "sandbox"
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "300"))   # 5 min max per APK
DOCKER_ENABLED  = os.getenv("SANDBOX_ENABLED", "true").lower() == "true"


# ── Docker availability check ──────────────────────────────────────────────────

def _docker_available() -> tuple[bool, str]:
    """Return (True, version_str) if Docker daemon is reachable, else (False, error)."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, result.stdout.strip()
        return False, result.stderr.strip() or "Docker daemon not responding"
    except FileNotFoundError:
        return False, "Docker CLI not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon connection timed out"
    except Exception as e:
        return False, str(e)


# ── Image build/check ──────────────────────────────────────────────────────────

def _ensure_image() -> tuple[bool, str]:
    """
    Check if sandbox image exists locally. If not, build it.
    Returns (success, message).
    """
    # Check if image exists
    check = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True, text=True, timeout=10,
    )
    if check.returncode == 0:
        return True, f"Image {SANDBOX_IMAGE} ready"

    # Build it
    logger.info(f"Building sandbox image {SANDBOX_IMAGE}...")
    if not SANDBOX_DIR.exists():
        return False, f"Sandbox directory not found: {SANDBOX_DIR}"

    build = subprocess.run(
        ["docker", "build", "-t", SANDBOX_IMAGE, str(SANDBOX_DIR)],
        capture_output=True, text=True, timeout=600,  # 10 min for first build
    )
    if build.returncode == 0:
        logger.info("Sandbox image built successfully")
        return True, "Image built successfully"
    return False, f"Image build failed: {build.stderr[-500:]}"


# ── Container runner ───────────────────────────────────────────────────────────

def _run_container(apk_path: str) -> dict:
    """
    Spin up sandbox container, mount APK, collect results.
    Returns the parsed JSON result from the container.
    """
    apk_abs = Path(apk_path).resolve()
    if not apk_abs.exists():
        return {"sandbox_available": False, "error": f"APK not found: {apk_path}"}

    # Use a temp dir for output (container writes result.json here)
    with tempfile.TemporaryDirectory() as tmp_out:
        out_dir  = Path(tmp_out)
        out_file = out_dir / "result.json"

        # Container name for tracking
        container_name = f"droidraksha-sandbox-{uuid.uuid4().hex[:8]}"

        # Build docker run command
        # On Windows, paths need to be in proper format
        apk_mount = str(apk_abs).replace("\\", "/")
        out_mount = str(out_dir).replace("\\", "/")

        cmd = [
            "docker", "run",
            "--rm",                              # auto-remove after exit
            "--name", container_name,
            "--memory", "2g",                    # 2GB RAM limit
            "--cpus", "2",                       # 2 CPU cores max
            "--network", "none",                 # no network access from sandbox
            "--read-only",                       # read-only root filesystem
            "--tmpfs", "/tmp:size=256m",          # allow writes to /tmp
            "--tmpfs", "/work:size=1g",           # decompile workspace
            "-v", f"{apk_abs}:/input/app.apk:ro",  # APK input (read-only)
            "-v", f"{out_dir}:/output",           # results output
            SANDBOX_IMAGE,
            "--apk", "/input/app.apk",
            "--out", "/output/result.json",
        ]

        logger.info(f"Starting sandbox container {container_name} for {apk_abs.name}")
        start = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SANDBOX_TIMEOUT,
            )

            elapsed = round(time.time() - start, 1)
            logger.info(f"Container {container_name} exited in {elapsed}s (rc={proc.returncode})")

            if proc.stdout:
                for line in proc.stdout.strip().split("\n"):
                    logger.debug(f"[container] {line}")

            if not out_file.exists():
                return {
                    "sandbox_available": False,
                    "error": f"Container produced no output. stderr: {proc.stderr[-300:]}",
                    "container_logs": proc.stdout[-500:],
                }

            raw = out_file.read_text(encoding="utf-8")
            result = json.loads(raw)
            result["container_elapsed_sec"] = elapsed
            return result

        except subprocess.TimeoutExpired:
            # Kill the container if it's still running
            subprocess.run(["docker", "kill", container_name], capture_output=True)
            return {
                "sandbox_available": False,
                "error": f"Sandbox timed out after {SANDBOX_TIMEOUT}s",
            }
        except json.JSONDecodeError as e:
            return {
                "sandbox_available": False,
                "error": f"Invalid JSON from container: {e}",
            }
        except Exception as e:
            return {
                "sandbox_available": False,
                "error": f"Container error: {e}",
            }


# ── Public API ─────────────────────────────────────────────────────────────────

def run(apk_path: str) -> dict:
    """
    Main entry point. Run full sandbox analysis on an APK.

    Returns a dict with keys:
      sandbox_available (bool)
      behavioral_score  (dict: score, level, flags, summary)
      smali_analysis    (dict: api calls, crypto, antianalysis...)
      manifest          (dict)
      resources         (dict)
      error             (str | None)
    """
    if not DOCKER_ENABLED:
        return {
            "sandbox_available": False,
            "error": "Sandbox disabled via SANDBOX_ENABLED=false",
        }

    # 1. Check Docker daemon
    docker_ok, docker_msg = _docker_available()
    if not docker_ok:
        logger.warning(f"Docker unavailable: {docker_msg}")
        return {
            "sandbox_available": False,
            "error": f"Docker daemon not running: {docker_msg}. Start Docker Desktop to enable sandbox.",
        }

    logger.info(f"Docker OK (v{docker_msg})")

    # 2. Ensure sandbox image exists
    image_ok, image_msg = _ensure_image()
    if not image_ok:
        logger.error(f"Sandbox image unavailable: {image_msg}")
        return {
            "sandbox_available": False,
            "error": image_msg,
        }

    # 3. Run container
    return _run_container(apk_path)

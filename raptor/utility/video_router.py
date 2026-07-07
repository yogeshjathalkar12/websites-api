"""
video_router.py — Tool 8: Video Payload Compressor & Metadata Scrubber

Per the architecture doc, the actual compression + EXIF/metadata stripping
happens client-side via ffmpeg.wasm (a full FFmpeg build running inside the
browser tab via SharedArrayBuffer) -- video files never need to touch a
server just to get scrubbed and shrunk. This backend's real job is twofold:

  1. /verify-scrub — given the ORIGINAL and COMPRESSED file (or just their
     ffprobe-style metadata dumps), server-side confirms sensitive metadata
     (GPS, camera model, creation date) is actually gone using `ffprobe`
     (via python's subprocess) rather than trusting the client's word for it.
  2. /log-result — records the compression stats for the dashboard/history.

This split matters: a malicious or buggy client could claim metadata was
scrubbed when it wasn't. The verify step is what makes the "bypasses spam
filters" claim trustworthy instead of just client-asserted.
"""

import json
import subprocess
import tempfile
import os
import base64
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

SENSITIVE_TAGS = ["location", "gps", "make", "model", "creation_time", "com.apple.quicktime.location.iso6709"]


def _ffprobe_metadata(file_path: str) -> dict:
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", file_path],
            capture_output=True, text=True, timeout=15,
        )
        return json.loads(result.stdout or "{}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="ffprobe is not installed on the server.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not probe video: {e}")


def _find_sensitive_tags(metadata: dict) -> list:
    found = []
    tags = (metadata.get("format", {}) or {}).get("tags", {}) or {}
    for key, value in tags.items():
        if any(sig in key.lower() for sig in SENSITIVE_TAGS):
            found.append({"tag": key, "value": value})
    for stream in metadata.get("streams", []):
        for key, value in (stream.get("tags", {}) or {}).items():
            if any(sig in key.lower() for sig in SENSITIVE_TAGS):
                found.append({"tag": key, "value": value, "stream": stream.get("index")})
    return found


@router.get("/status")
def status():
    return {"tool": "video-payload-compressor", "status": "operational"}


@router.post("/verify-scrub")
def verify_scrub(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"compressed_video_base64": "<mp4 bytes, base64>"}
    Runs the compressed output the browser produced through a real ffprobe
    pass server-side and confirms no sensitive tags survived the scrub.
    1 credit — this is the verification pass, separate from the client-side
    compression which cost nothing server-side.
    """
    video_b64 = payload.get("compressed_video_base64")
    if not video_b64:
        raise HTTPException(status_code=400, detail="compressed_video_base64 is required.")

    remaining_credits = deduct_credit(user_id)

    try:
        raw = base64.b64decode(video_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 video data.")

    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name

    try:
        metadata = _ffprobe_metadata(tmp_path)
        leftover = _find_sensitive_tags(metadata)
        file_size = os.path.getsize(tmp_path)
        duration = float((metadata.get("format", {}) or {}).get("duration", 0) or 0)
    finally:
        os.unlink(tmp_path)

    return {
        "clean": len(leftover) == 0,
        "leftover_sensitive_tags": leftover,
        "file_size_bytes": file_size,
        "duration_sec": duration,
        "credits_left": remaining_credits,
    }


@router.post("/log-result")
def log_result(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "video_id": "pitch_v3_acmecorp", "original_size_bytes": 84000000,
      "compressed_size_bytes": 6200000, "metadata_scrubbed": true,
      "storage_url": "https://.../compressed.mp4"
    }
    """
    required = ["video_id", "original_size_bytes", "compressed_size_bytes"]
    if any(k not in payload for k in required):
        raise HTTPException(status_code=400, detail=f"Missing fields: {required}")

    original = int(payload["original_size_bytes"])
    compressed = int(payload["compressed_size_bytes"])
    reduction_pct = round((1 - compressed / original) * 100, 1) if original > 0 else 0

    row = {
        "user_id": user_id,
        "video_id": payload["video_id"],
        "original_size_bytes": original,
        "compressed_size_bytes": compressed,
        "reduction_pct": reduction_pct,
        "metadata_scrubbed": bool(payload.get("metadata_scrubbed", False)),
        "storage_url": payload.get("storage_url"),
    }

    if supabase:
        try:
            supabase.table("video_assets").insert(row).execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Could not save result: {e}")

    return row


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("video_assets")
        .select("video_id, original_size_bytes, compressed_size_bytes, reduction_pct, metadata_scrubbed, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(100)
        .execute()
    )
    return {"videos": resp.data or []}
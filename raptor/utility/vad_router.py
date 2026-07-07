"""
vad_router.py — Tool 6: WASM-Powered Call Audio VAD

The actual DSP (WebRTC VAD frame analysis, 10-30ms buffer slicing, energy
thresholding) runs entirely client-side via WASM in the browser -- that's
the whole point of this tool: raw call audio never has to leave the user's
machine just to get silence-stripped. This backend's job is narrower and
just as real: verify the credit spend, persist the *result* of that
client-side processing (compression ratio, final duration, a pointer to
wherever the compressed blob ended up), and serve history back to the UI.

If the frontend instead wants server-side processing for a batch of files
(e.g. bulk cleanup of an existing call archive), point it at /process-batch,
which does real energy-threshold VAD in Python using `webrtcvad` + `wave` on
uploaded PCM/WAV bytes -- no WASM required server-side since it's already native.
"""

import io
import wave
import base64
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

try:
    import webrtcvad
    _vad_available = True
except ImportError:
    _vad_available = False


@router.get("/status")
def status():
    return {"tool": "call-audio-vad", "status": "operational", "server_side_vad_available": _vad_available}


@router.post("/log-result")
def log_client_result(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "call_id": "call_2026_07_04_prospectX",
      "original_duration_sec": 3612, "compressed_duration_sec": 940,
      "storage_url": "https://.../compressed_call.webm"
    }
    Called after the browser's WASM VAD pass finishes. 1 credit per call processed.
    """
    required = ["call_id", "original_duration_sec", "compressed_duration_sec"]
    if any(k not in payload for k in required):
        raise HTTPException(status_code=400, detail=f"Missing fields: {required}")

    remaining_credits = deduct_credit(user_id)

    original = float(payload["original_duration_sec"])
    compressed = float(payload["compressed_duration_sec"])
    silence_removed_pct = round((1 - compressed / original) * 100, 1) if original > 0 else 0

    row = {
        "user_id": user_id,
        "call_id": payload["call_id"],
        "original_duration_sec": original,
        "compressed_duration_sec": compressed,
        "silence_removed_pct": silence_removed_pct,
        "storage_url": payload.get("storage_url"),
    }

    if supabase:
        try:
            supabase.table("call_recordings").insert(row).execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Could not save result: {e}")

    return {**row, "credits_left": remaining_credits}


@router.post("/process-batch")
def process_batch(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"call_id": "...", "wav_base64": "<mono 16-bit PCM WAV, base64>"}
    Real server-side VAD using Google's WebRTC VAD (via the `webrtcvad`
    Python binding) for cases where processing needs to happen off a batch
    upload rather than live in a browser tab. Splits into 30ms frames,
    classifies speech vs. silence, and reports how much was voice.
    """
    if not _vad_available:
        raise HTTPException(status_code=500, detail="webrtcvad is not installed on the server (pip install webrtcvad).")

    call_id = payload.get("call_id")
    wav_b64 = payload.get("wav_base64")
    if not call_id or not wav_b64:
        raise HTTPException(status_code=400, detail="call_id and wav_base64 are required.")

    remaining_credits = deduct_credit(user_id)

    try:
        raw = base64.b64decode(wav_b64)
        wf = wave.open(io.BytesIO(raw), "rb")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse WAV data.")

    if wf.getnchannels() != 1 or wf.getsampwidth() != 2 or wf.getframerate() not in (8000, 16000, 32000, 48000):
        raise HTTPException(status_code=400, detail="WAV must be mono, 16-bit PCM, at 8/16/32/48kHz for VAD.")

    sample_rate = wf.getframerate()
    pcm = wf.readframes(wf.getnframes())
    wf.close()

    vad = webrtcvad.Vad(2)  # aggressiveness 0-3
    frame_ms = 30
    frame_bytes = int(sample_rate * (frame_ms / 1000.0) * 2)  # 2 bytes/sample

    voiced_frames = 0
    total_frames = 0
    for i in range(0, len(pcm) - frame_bytes, frame_bytes):
        frame = pcm[i:i + frame_bytes]
        total_frames += 1
        if vad.is_speech(frame, sample_rate):
            voiced_frames += 1

    voiced_pct = round((voiced_frames / total_frames) * 100, 1) if total_frames else 0
    original_duration = len(pcm) / (sample_rate * 2)
    compressed_duration = original_duration * (voiced_frames / total_frames) if total_frames else 0

    row = {
        "user_id": user_id,
        "call_id": call_id,
        "original_duration_sec": round(original_duration, 1),
        "compressed_duration_sec": round(compressed_duration, 1),
        "silence_removed_pct": round(100 - voiced_pct, 1),
    }

    if supabase:
        try:
            supabase.table("call_recordings").insert(row).execute()
        except Exception:
            pass

    return {**row, "voiced_pct": voiced_pct, "credits_left": remaining_credits}


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("call_recordings")
        .select("call_id, original_duration_sec, compressed_duration_sec, silence_removed_pct, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(100)
        .execute()
    )
    return {"recordings": resp.data or []}
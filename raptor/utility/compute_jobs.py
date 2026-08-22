"""
compute_jobs.py — shared bookkeeping for CPU-bound background jobs

Used by kmeans_router.py and montecarlo_router.py to move heavy pure-Python
computation off the request thread. FastAPI's BackgroundTasks runs the
target function in a threadpool executor rather than the main asyncio event
loop, so other requests keep being served while a Monte Carlo run or a
K-Means clustering job grinds through its loop -- that's the actual fix for
"one user's simulation blocks everyone else."

Honest limit on this approach, worth knowing before you lean on it harder:
Python's GIL means threads don't get true CPU parallelism -- two CPU-bound
jobs running "concurrently" via BackgroundTasks still take turns on the CPU,
they just no longer block the event loop from handling I/O-bound requests
(auth checks, Supabase queries, etc.) in the meantime. That's a real and
sufficient fix for "the whole API hangs during a simulation." It is NOT the
same as horizontal scaling. If Monte Carlo/K-Means usage itself becomes the
bottleneck (many simultaneous heavy jobs, not just heavy jobs blocking
everything else), the next real step is a separate worker process/dyno
(Celery+Redis or RQ) so compute runs on genuinely different CPU cores. Don't
build that yet -- it's real infra to operate, and you have zero users right
now. This is the right-sized fix for where you are.
"""

from datetime import datetime, timezone
from fastapi import HTTPException

from .raptor_auth import supabase


def create_job(user_id: str, tool: str, input_payload: dict) -> str:
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")
    resp = supabase.table("compute_jobs").insert({
        "user_id": user_id,
        "tool": tool,
        "status": "queued",
        "input": input_payload,
    }).execute()
    return resp.data[0]["id"]


def mark_running(job_id: str) -> None:
    if supabase:
        supabase.table("compute_jobs").update({"status": "running"}).eq("id", job_id).execute()


def mark_done(job_id: str, result: dict) -> None:
    if supabase:
        supabase.table("compute_jobs").update({
            "status": "done",
            "result": result,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", job_id).execute()


def mark_failed(job_id: str, error: str) -> None:
    if supabase:
        supabase.table("compute_jobs").update({
            "status": "failed",
            "error": error,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", job_id).execute()


def get_job(user_id: str, job_id: str) -> dict:
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")
    resp = (
        supabase.table("compute_jobs")
        .select("*")
        .eq("id", job_id)
        .eq("user_id", user_id)
        .single()
        .execute()
    )
    if not resp.data:
        raise HTTPException(status_code=404, detail="Job not found.")
    return resp.data
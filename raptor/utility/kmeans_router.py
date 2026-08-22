"""
kmeans_router.py — Tool 7: K-Means ICP Clustering Engine

Real k-means, not a stub: Z-score normalization per numeric field,
k-means++ centroid seeding (better than pure-random -- avoids bad
convergence on unlucky initial draws), Euclidean distance assignment,
centroid recomputation, repeated to convergence or a max-iteration cap.
Pure Python (no numpy dependency) so it runs anywhere this FastAPI app runs.

BACKGROUND JOB PATTERN: the clustering loop itself (potentially hundreds of
iterations over up to 5000 rows) now runs via BackgroundTasks instead of
inline in the request -- see compute_jobs.py's docstring for exactly what
this does and doesn't fix. POST /cluster validates input, deducts the
credit, and returns a job_id immediately; GET /job/{job_id} polls for the
result, same shape as the AI Content Suite's video pipeline polling.
"""

import random
import math
from fastapi import APIRouter, HTTPException, Depends, Body, BackgroundTasks

from .raptor_auth import get_current_user, deduct_credit, supabase
from . import compute_jobs

router = APIRouter()

MAX_ROWS = 5000
MAX_ITERATIONS = 100


def _zscore_normalize(rows: list, fields: list):
    means = {f: sum(r[f] for r in rows) / len(rows) for f in fields}
    stds = {}
    for f in fields:
        variance = sum((r[f] - means[f]) ** 2 for r in rows) / len(rows)
        stds[f] = math.sqrt(variance) or 1.0  # avoid div-by-zero on constant columns

    normalized = []
    for r in rows:
        normalized.append([(r[f] - means[f]) / stds[f] for f in fields])
    return normalized, means, stds


def _euclidean(a, b):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _kmeans_plus_plus_init(points: list, k: int, rng: random.Random):
    centroids = [rng.choice(points)]
    while len(centroids) < k:
        distances = [min(_euclidean(p, c) ** 2 for c in centroids) for p in points]
        total = sum(distances) or 1.0
        r = rng.random() * total
        cumulative = 0.0
        for point, dist in zip(points, distances):
            cumulative += dist
            if cumulative >= r:
                centroids.append(point)
                break
        else:
            centroids.append(rng.choice(points))
    return centroids


def _run_kmeans(points: list, k: int, seed: int = 42):
    rng = random.Random(seed)
    centroids = _kmeans_plus_plus_init(points, k, rng)
    assignments = [0] * len(points)

    for _ in range(MAX_ITERATIONS):
        new_assignments = []
        for p in points:
            distances = [_euclidean(p, c) for c in centroids]
            new_assignments.append(distances.index(min(distances)))

        if new_assignments == assignments:
            break
        assignments = new_assignments

        new_centroids = []
        for cluster_idx in range(k):
            members = [p for p, a in zip(points, assignments) if a == cluster_idx]
            if not members:
                new_centroids.append(centroids[cluster_idx])  # keep stale centroid if cluster emptied
                continue
            dims = len(members[0])
            centroid = [sum(m[d] for m in members) / len(members) for d in range(dims)]
            new_centroids.append(centroid)
        centroids = new_centroids

    return assignments, centroids


def _execute_cluster_job(job_id: str, user_id: str, rows: list, fields: list, k: int, label_field: str | None):
    """Runs off the request thread via BackgroundTasks. Any failure is caught
    and recorded on the job row rather than raised -- there's no request left
    to raise it to by the time this runs."""
    compute_jobs.mark_running(job_id)
    try:
        normalized_points, means, stds = _zscore_normalize(rows, fields)
        assignments, centroids = _run_kmeans(normalized_points, k)

        clusters = {i: [] for i in range(k)}
        for row, cluster_idx in zip(rows, assignments):
            entry = {"row": row}
            if label_field and label_field in row:
                entry["label"] = row[label_field]
            clusters[cluster_idx].append(entry)

        denorm_centroids = []
        for c in centroids:
            denorm_centroids.append({f: round(c[i] * stds[f] + means[f], 2) for i, f in enumerate(fields)})

        cluster_summary = [
            {
                "cluster_id": i,
                "size": len(clusters[i]),
                "centroid": denorm_centroids[i],
                "members": clusters[i],
            }
            for i in range(k)
        ]

        if supabase:
            try:
                supabase.table("icp_clusters").insert({
                    "user_id": user_id,
                    "k": k,
                    "fields": fields,
                    "row_count": len(rows),
                    "result": cluster_summary,
                }).execute()
            except Exception:
                pass

        compute_jobs.mark_done(job_id, {"clusters": cluster_summary})
    except Exception as e:
        compute_jobs.mark_failed(job_id, str(e))


@router.get("/status")
def status():
    return {"tool": "kmeans-icp-clustering", "status": "operational"}


@router.post("/cluster")
def cluster(background_tasks: BackgroundTasks, payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "rows": [{"company": "Acme", "revenue": 4200000, "employees": 80, ...}, ...],
      "fields": ["revenue", "employees"],   # numeric fields to cluster on
      "k": 3,
      "label_field": "company"              # optional, for readable output
    }
    Returns {"job_id": ..., "status": "queued"} immediately. Poll
    GET /job/{job_id} for the result -- see kmeans's own history via
    /history once done, same as before.
    """
    rows = payload.get("rows") or []
    fields = payload.get("fields") or []
    k = int(payload.get("k", 3))
    label_field = payload.get("label_field")

    if not rows or not fields:
        raise HTTPException(status_code=400, detail="Provide 'rows' and 'fields' (numeric columns to cluster on).")
    if len(rows) > MAX_ROWS:
        raise HTTPException(status_code=400, detail=f"Max {MAX_ROWS} rows server-side — use the in-browser tool for larger sets.")
    if k < 2 or k > min(10, len(rows)):
        raise HTTPException(status_code=400, detail="k must be between 2 and 10 (and less than the row count).")

    for r in rows:
        for f in fields:
            if f not in r or not isinstance(r[f], (int, float)):
                raise HTTPException(status_code=400, detail=f"Row missing numeric field '{f}': {r}")

    # Credit is deducted up front, synchronously -- the user shouldn't be
    # able to queue free jobs by walking away before a background task
    # would otherwise have deducted it.
    remaining_credits = deduct_credit(user_id)

    job_id = compute_jobs.create_job(user_id, "kmeans", {"row_count": len(rows), "fields": fields, "k": k})
    background_tasks.add_task(_execute_cluster_job, job_id, user_id, rows, fields, k, label_field)

    return {"job_id": job_id, "status": "queued", "credits_left": remaining_credits}


@router.get("/job/{job_id}")
def get_job(job_id: str, user_id: str = Depends(get_current_user)):
    return compute_jobs.get_job(user_id, job_id)


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("icp_clusters")
        .select("id, k, fields, row_count, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    return {"runs": resp.data or []}
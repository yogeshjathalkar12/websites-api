"""
montecarlo_router.py — Tool 9: Monte Carlo Pipeline Simulator

Real stochastic simulation, not a canned distribution: for each of N
iterations, every deal in the pipeline is independently "won" or "lost"
via a random draw weighted by its stated close probability, and the total
revenue for that run is recorded. Across 10,000 runs this produces an
empirical distribution the P10/P50/P90 percentiles are read directly off
of -- no Gaussian assumption is imposed on the shape, it emerges from the
underlying deal probabilities the way it would in reality (a pipeline with
one huge low-probability deal is visibly skewed, not artificially bell-shaped).
"""

import random
import math
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

DEFAULT_ITERATIONS = 10000
MAX_ITERATIONS = 50000
MAX_DEALS = 500


def _percentile(sorted_values: list, pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (pct / 100)
    floor_idx, ceil_idx = math.floor(k), math.ceil(k)
    if floor_idx == ceil_idx:
        return sorted_values[int(k)]
    lower = sorted_values[floor_idx] * (ceil_idx - k)
    upper = sorted_values[ceil_idx] * (k - floor_idx)
    return lower + upper


def _run_simulation(deals: list, iterations: int, seed: int = None):
    rng = random.Random(seed)
    outcomes = []

    for _ in range(iterations):
        total = 0.0
        for deal in deals:
            if rng.random() < deal["probability"]:
                total += deal["value"]
        outcomes.append(total)

    outcomes.sort()
    return outcomes


@router.get("/status")
def status():
    return {"tool": "montecarlo-pipeline-simulator", "status": "operational"}


@router.post("/simulate")
def simulate(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "deals": [{"name": "Panchshil Realty", "value": 400000, "probability": 0.4}, ...],
      "iterations": 10000,
      "bucket_count": 20     # for the histogram
    }
    probability must be a 0-1 float (40% -> 0.4). 1 credit per simulation run
    (not per iteration/deal — those are free compute inside a single run).
    """
    deals_input = payload.get("deals") or []
    iterations = min(int(payload.get("iterations", DEFAULT_ITERATIONS)), MAX_ITERATIONS)
    bucket_count = max(5, min(int(payload.get("bucket_count", 20)), 50))

    if not deals_input:
        raise HTTPException(status_code=400, detail="Provide a non-empty 'deals' list.")
    if len(deals_input) > MAX_DEALS:
        raise HTTPException(status_code=400, detail=f"Max {MAX_DEALS} deals per simulation.")

    deals = []
    for d in deals_input:
        try:
            value = float(d["value"])
            probability = float(d["probability"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"Malformed deal entry: {d}")
        if not (0 <= probability <= 1):
            raise HTTPException(status_code=400, detail=f"Probability must be between 0 and 1: {d}")
        if value < 0:
            raise HTTPException(status_code=400, detail=f"Deal value cannot be negative: {d}")
        deals.append({"name": d.get("name", "Unnamed deal"), "value": value, "probability": probability})

    remaining_credits = deduct_credit(user_id)

    outcomes = _run_simulation(deals, iterations)

    p10 = _percentile(outcomes, 10)
    p50 = _percentile(outcomes, 50)
    p90 = _percentile(outcomes, 90)
    expected_value = sum(d["value"] * d["probability"] for d in deals)
    mean_outcome = sum(outcomes) / len(outcomes)
    best_case = outcomes[-1]
    worst_case = outcomes[0]

    # Histogram for the frontend to render a bell/skew curve without
    # shipping all 10,000 raw floats over the wire.
    bucket_width = (best_case - worst_case) / bucket_count if best_case > worst_case else 1
    histogram = [0] * bucket_count
    for v in outcomes:
        idx = min(int((v - worst_case) / bucket_width), bucket_count - 1) if bucket_width else 0
        histogram[idx] += 1

    buckets = [
        {"range_start": round(worst_case + i * bucket_width, 2),
         "range_end": round(worst_case + (i + 1) * bucket_width, 2),
         "count": histogram[i]}
        for i in range(bucket_count)
    ]

    result = {
        "deal_count": len(deals),
        "iterations": iterations,
        "expected_value_naive": round(expected_value, 2),
        "simulated_mean": round(mean_outcome, 2),
        "p10_worst_case": round(p10, 2),
        "p50_expected": round(p50, 2),
        "p90_best_case": round(p90, 2),
        "absolute_worst": round(worst_case, 2),
        "absolute_best": round(best_case, 2),
        "histogram": buckets,
        "credits_left": remaining_credits,
    }

    if supabase:
        try:
            supabase.table("simulation_runs").insert({
                "user_id": user_id,
                "deal_count": len(deals),
                "iterations": iterations,
                "p10": result["p10_worst_case"],
                "p50": result["p50_expected"],
                "p90": result["p90_best_case"],
                "deals_snapshot": deals,
            }).execute()
        except Exception:
            pass

    return result


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("simulation_runs")
        .select("id, deal_count, iterations, p10, p50, p90, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    return {"runs": resp.data or []}
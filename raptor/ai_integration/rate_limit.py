"""
rate_limit.py — per-user, per-modality generation limits

Why this exists even though generation cost sits on the USER's own API key
(see content_router.py's credits note): the risk isn't their bill, it's
support burden on YOUR side — a runaway frontend loop or a scripted abuser
hammering /pipeline can (a) hit provider-side rate limits and generate a
wall of confusing 429 support tickets, (b) run up your Render compute on
synchronous image calls that can take 10-30s each, and (c) in the video
case, leave a pile of orphaned polling jobs. Text is cheap and fast enough
that it isn't gated here; image and video are, because those are the two
modalities where a tight loop actually costs YOU something (server time,
job bookkeeping) independent of whose API key pays the provider.

Limits are deliberately generous — this is an abuse backstop, not a
product-tier paywall. Tighten via MODALITY_LIMITS if real usage says otherwise.
"""

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

from raptor.utility.raptor_auth import supabase

# (max generations, window in minutes) per modality per user.
MODALITY_LIMITS = {
    "image": (20, 60),
    "video": (5, 60),
}


def check_rate_limit(user_id: str, modality: str) -> None:
    """Raises 429 if the user has hit their window limit for this modality. No-op for text."""
    if modality not in MODALITY_LIMITS:
        return
    if not supabase:
        return  # fail open if DB is down — don't block generation on a rate-limit check outage

    limit, window_minutes = MODALITY_LIMITS[modality]
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()

    resp = (
        supabase.table("content_pipelines")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .contains("modalities", [modality])
        .gte("created_at", since)
        .execute()
    )

    count = resp.count or 0
    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"You've hit the {modality} generation limit ({limit} per {window_minutes} min). Try again shortly.",
        )
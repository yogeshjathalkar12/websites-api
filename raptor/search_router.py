"""raptor/search_router.py: web search for the Raptor desktop app (prospect search, email and person finders, competitor radar).

The search key (SerpAPI) lives here on the server so it never ships inside the desktop app. Who may search: a signed-in Raptor user, checked
by the same Supabase sign-in check every other Raptor route uses (raptor_auth.get_current_user). Each user is limited per minute and per day so
one account cannot drain the shared search quota.

Mounted at /api/raptor/search:  GET /api/raptor/search?query=...   with   Authorization: Bearer <the user's Supabase token>
Returns SerpAPI's JSON unchanged (the desktop reads organic_results, ads, etc.).

Needs one environment variable on this service: SERPAPI_KEY.
"""
import logging
import os
import threading
import time
from typing import Optional

import requests
from fastapi import APIRouter, Depends, HTTPException

from .utility.raptor_auth import get_current_user

log = logging.getLogger("raptor_search")

router = APIRouter()

SERPAPI_URL = "https://serpapi.com/search.json"
PER_MINUTE = 40
PER_DAY = 600
MAX_QUERY = 500
MAX_LOCATION = 120

_calls: dict = {}          # user id -> list of call times (monotonic seconds), newest last
_calls_lock = threading.Lock()


def _check_limits(user_id: str, now: float) -> None:
    """Raises 429 if this user searched too often. Records the call otherwise. Resets when the server restarts, which is fine for a safety limit."""
    with _calls_lock:
        recent = [t for t in _calls.get(user_id, []) if now - t < 86400]
        if len(recent) >= PER_DAY:
            raise HTTPException(status_code=429, detail="Daily search limit reached. It resets within 24 hours.")
        if sum(1 for t in recent if now - t < 60) >= PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many searches. Try again in a minute.")
        recent.append(now)
        _calls[user_id] = recent
        if len(_calls) > 5000:                      # keep memory bounded: forget users with no call today
            for uid in [u for u, ts in _calls.items() if not ts or now - ts[-1] >= 86400]:
                _calls.pop(uid, None)


@router.get("")
def search(query: str, location: Optional[str] = None, gl: Optional[str] = None, user_id: str = Depends(get_current_user)):
    """`location` ("Pune, Maharashtra, India") and `gl` (a two-letter country code) ask Google for that place; both are optional."""
    query = (query or "").strip()
    if not query or len(query) > MAX_QUERY:
        raise HTTPException(status_code=400, detail="Invalid query")
    location = " ".join((location or "").split())[:MAX_LOCATION] or None
    gl = (gl or "").strip().lower()
    gl = gl if len(gl) == 2 and gl.isalpha() else None

    key = os.getenv("SERPAPI_KEY")
    if not key:
        raise HTTPException(status_code=500, detail="Search is not set up on the server yet.")

    _check_limits(user_id, time.monotonic())

    try:
        params = {"q": query, "api_key": key}
        if location:
            params["location"] = location
        if gl:
            params["gl"] = gl
        response = requests.get(SERPAPI_URL, params=params, timeout=20)
        response.raise_for_status()
    except requests.RequestException as e:
        log.error("SerpAPI request failed: %s", e)
        raise HTTPException(status_code=502, detail="Upstream search request failed")
    return response.json()

"""
chronos_router.py — Tool 5: Chronos Timezone Optimization Engine

Pipeline: raw city text -> lat/lng (geocoding) -> timezone polygon lookup
(point-in-polygon via the `timezonefinder` package, which ships an indexed
version of the open-source timezone-boundary-builder shapefiles) -> exact
UTC offset for a given send date via `zoneinfo`, correctly accounting for
DST on that specific date rather than a hardcoded UTC offset table.

Requires: pip install timezonefinder geopy --break-system-packages
"""

import os
from datetime import datetime, time as dtime
from zoneinfo import ZoneInfo
from fastapi import APIRouter, HTTPException, Depends, Body
import httpx

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

try:
    from timezonefinder import TimezoneFinder
    _tf = TimezoneFinder()
except ImportError:
    _tf = None

# Nominatim (OpenStreetMap) geocoding -- free, no API key, rate-limited to
# 1 req/sec per their usage policy. A production deployment with real volume
# should cache resolved city->lat/lng pairs (we do, in geocode_cache table)
# so the same "Austin, Texas" string isn't re-geocoded on every send.
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = "ShoonyaOrigins-Raptor-Chronos/1.0 (hello@shoonyaorigins.com)"


def _geocode(place_text: str):
    if not supabase:
        cached = None
    else:
        cached_resp = supabase.table("geocode_cache").select("lat, lng, resolved_name").eq("query", place_text.lower()).execute()
        cached = cached_resp.data[0] if cached_resp.data else None

    if cached:
        return cached["lat"], cached["lng"], cached["resolved_name"]

    resp = httpx.get(
        NOMINATIM_URL,
        params={"q": place_text, "format": "json", "limit": 1},
        headers={"User-Agent": USER_AGENT},
        timeout=6,
    )
    resp.raise_for_status()
    results = resp.json()
    if not results:
        raise HTTPException(status_code=404, detail=f"Could not geocode '{place_text}'.")

    lat, lng = float(results[0]["lat"]), float(results[0]["lon"])
    resolved_name = results[0].get("display_name", place_text)

    if supabase:
        try:
            supabase.table("geocode_cache").insert({
                "query": place_text.lower(), "lat": lat, "lng": lng, "resolved_name": resolved_name,
            }).execute()
        except Exception:
            pass

    return lat, lng, resolved_name


def _resolve_timezone(lat: float, lng: float) -> str:
    if not _tf:
        raise HTTPException(status_code=500, detail="timezonefinder is not installed on the server.")
    tz_name = _tf.timezone_at(lat=lat, lng=lng)
    if not tz_name:
        raise HTTPException(status_code=404, detail="No timezone polygon found for that coordinate (likely open ocean).")
    return tz_name


@router.get("/status")
def status():
    return {"tool": "chronos-engine", "status": "operational", "timezonefinder_loaded": _tf is not None}


@router.post("/resolve")
def resolve_send_time(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "place": "Austin, Texas",
      "target_local_time": "08:45",   # HH:MM in the prospect's local time
      "target_date": "2026-07-10"      # optional, defaults to tomorrow
    }
    Returns the exact UTC datetime to schedule the send for, with DST
    already accounted for on that specific date.
    """
    place = (payload.get("place") or "").strip()
    target_local_time = payload.get("target_local_time", "08:45")
    target_date_str = payload.get("target_date")

    if not place:
        raise HTTPException(status_code=400, detail="'place' is required (e.g. 'Pune, India').")

    try:
        hour, minute = map(int, target_local_time.split(":"))
    except Exception:
        raise HTTPException(status_code=400, detail="target_local_time must be 'HH:MM'.")

    remaining_credits = deduct_credit(user_id)

    lat, lng, resolved_name = _geocode(place)
    tz_name = _resolve_timezone(lat, lng)
    tzinfo = ZoneInfo(tz_name)

    if target_date_str:
        try:
            target_date = datetime.strptime(target_date_str, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="target_date must be 'YYYY-MM-DD'.")
    else:
        target_date = (datetime.now(tzinfo) ).date()

    local_dt = datetime.combine(target_date, dtime(hour, minute), tzinfo=tzinfo)
    utc_dt = local_dt.astimezone(ZoneInfo("UTC"))
    utc_offset = local_dt.utcoffset()
    offset_hours = utc_offset.total_seconds() / 3600 if utc_offset else 0

    result = {
        "input_place": place,
        "resolved_name": resolved_name,
        "lat": lat,
        "lng": lng,
        "timezone": tz_name,
        "utc_offset_hours": offset_hours,
        "local_send_time": local_dt.isoformat(),
        "send_after_utc": utc_dt.isoformat(),
        "credits_left": remaining_credits,
    }

    if supabase:
        try:
            supabase.table("scheduled_sends").insert({
                "user_id": user_id,
                "place": place,
                "timezone": tz_name,
                "local_send_time": local_dt.isoformat(),
                "send_after_utc": utc_dt.isoformat(),
            }).execute()
        except Exception:
            pass

    return result


@router.get("/scheduled")
def get_scheduled(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("scheduled_sends")
        .select("place, timezone, local_send_time, send_after_utc, created_at")
        .eq("user_id", user_id)
        .order("send_after_utc", desc=False)
        .limit(100)
        .execute()
    )
    return {"scheduled": resp.data or []}

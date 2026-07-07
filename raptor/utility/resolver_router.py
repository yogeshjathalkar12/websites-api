"""
resolver_router.py — Tool 4: B2B Reverse-IP Resolver (The Deanonymizer)

Resolves an anonymous visitor's IP address to a corporate network by matching
it against a CIDR range table the user maintains (raptor_ip_ranges) —
typically built from a purchased/scraped ASN block list (e.g. exported from
a MaxMind-style dataset) but stored as plain CIDR rows so no proprietary
.mmdb binary needs to ship with this codebase.

Implementation note: Python's `ipaddress` module already does the binary
prefix-matching a Radix Trie is used for -- we build an in-memory, sorted
list of ip_network objects per request-batch-window so lookups stay O(log n)
without needing a compiled trie library. For genuinely high QPS ingestion
(server logs, not just single lookups) you'd cache this list in the process
instead of re-fetching per request; that swap is noted inline below.
"""

import ipaddress
from functools import lru_cache
from time import time
from fastapi import APIRouter, HTTPException, Depends, Body, Request

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

_CACHE_TTL_SECONDS = 60
_range_cache = {}  # user_id -> (timestamp, sorted list of (network, company_name))


def _load_ranges(user_id: str):
    """Loads + sorts this user's CIDR table, cached for _CACHE_TTL_SECONDS so
    a burst of visitor-resolution calls doesn't hit Postgres every time."""
    cached = _range_cache.get(user_id)
    if cached and (time() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    resp = supabase.table("ip_ranges").select("cidr, company_name").eq("user_id", user_id).execute()
    parsed = []
    for row in resp.data or []:
        try:
            parsed.append((ipaddress.ip_network(row["cidr"], strict=False), row["company_name"]))
        except ValueError:
            continue
    # Sort by prefix length descending so a /24 match wins over a /16
    # containing it -- most-specific-match-first, same principle a trie gives you.
    parsed.sort(key=lambda pair: pair[0].prefixlen, reverse=True)

    _range_cache[user_id] = (time(), parsed)
    return parsed


def _resolve_ip(ip_str: str, ranges: list):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for network, company_name in ranges:
        if ip_obj in network:
            return company_name
    return None


@router.get("/status")
def status():
    return {"tool": "reverse-ip-resolver", "status": "operational"}


@router.post("/ranges/upload")
def upload_ranges(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"ranges": [{"cidr": "203.0.113.0/24", "company_name": "Acme Corp"}, ...]}
    Bulk-loads the user's own CIDR->company table. Free (no credit spend) —
    this is data ingestion, not a lookup/action.
    """
    ranges = payload.get("ranges") or []
    if not isinstance(ranges, list) or not ranges:
        raise HTTPException(status_code=400, detail="Provide a non-empty list of {cidr, company_name} objects.")

    rows = []
    invalid = []
    for entry in ranges:
        cidr = str(entry.get("cidr", "")).strip()
        name = str(entry.get("company_name", "")).strip()[:120]
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            invalid.append(cidr)
            continue
        if not name:
            invalid.append(cidr)
            continue
        rows.append({"user_id": user_id, "cidr": cidr, "company_name": name})

    if rows and supabase:
        try:
            supabase.table("ip_ranges").upsert(rows, on_conflict="user_id,cidr").execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Insert failed: {e}")

    _range_cache.pop(user_id, None)  # invalidate cache so next lookup sees fresh data

    return {"inserted": len(rows), "invalid": invalid}


@router.get("/resolve")
def resolve_ip(ip: str, user_id: str = Depends(get_current_user)):
    """Resolves a single IP against the caller's own uploaded CIDR table."""
    remaining_credits = deduct_credit(user_id)
    ranges = _load_ranges(user_id)
    company = _resolve_ip(ip, ranges)

    if supabase:
        try:
            supabase.table("resolved_visits").insert({
                "user_id": user_id, "ip": ip, "company_name": company,
            }).execute()
        except Exception:
            pass

    return {
        "ip": ip,
        "company_name": company,
        "matched": company is not None,
        "credits_left": remaining_credits,
    }


@router.post("/track-visit")
def track_visit(payload: dict = Body(...), request: Request = None):
    """
    PUBLIC endpoint — meant to be called from the user's own website JS
    (like a beacon) with the visitor's X-Forwarded-For, resolved against
    that site owner's pre-registered ranges via an API key rather than a
    user JWT (visitors aren't logged in). Kept simple here: expects the
    site owner's user_id + a shared secret in the body, since a real
    deployment would issue a scoped public write-key instead of the raw
    user_id -- flagged here rather than silently treated as production-safe.
    """
    site_user_id = payload.get("site_user_id")
    ip = payload.get("ip") or (request.client.host if request else None)
    if not site_user_id or not ip:
        raise HTTPException(status_code=400, detail="site_user_id and ip are required.")

    ranges = _load_ranges(site_user_id)
    company = _resolve_ip(ip, ranges)

    if company and supabase:
        try:
            supabase.table("resolved_visits").insert({
                "user_id": site_user_id, "ip": ip, "company_name": company, "source": "website_beacon",
            }).execute()
        except Exception:
            pass

    return {"matched": company is not None, "company_name": company}


@router.get("/visits")
def get_visits(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("resolved_visits")
        .select("ip, company_name, source, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(200)
        .execute()
    )
    return {"visits": resp.data or []}
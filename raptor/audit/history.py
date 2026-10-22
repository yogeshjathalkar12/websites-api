"""raptor/audit/history.py: "Site history": what the Internet Archive's Wayback Machine has recorded of the company's home page.

Source: the Wayback Machine's own public index (CDX). It records a page only when its crawler visits, so the number of versions it holds is a
LOWER BOUND on how often the site really changed, and "no snapshot" never proves "no change". Everything here is `info` for that reason.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import fetcher
from .common import check, unknown

S = "history"
CDX = "https://web.archive.org/cdx/search/cdx"
CAP = 3000          # most versions counted; a busier page is shown as "3000+"


def _rows(url: str):
    res = fetcher.fetch(url, max_bytes=800_000, timeout=25)
    if res.error or res.status != 200:
        return None, (res.error_detail or "HTTP %s" % res.status)
    try:
        data = json.loads(res.body) if res.body.strip() else []
    except ValueError:
        return None, "the archive's answer could not be read"
    return data[1:] if data else [], ""


def _when(stamp: str):
    try:
        return datetime.strptime(stamp[:8], "%Y%m%d").date()
    except ValueError:
        return None


def run(site: dict, rows=None):
    """-> list of checks. `rows` lets tests supply the archive's answers: rows(kind) -> (list or None, reason)."""
    host = site["host"]
    verify = "Open web.archive.org/web/*/%s to see the calendar of snapshots." % host
    src = "Internet Archive Wayback Machine (CDX index)"
    since = (datetime.now(timezone.utc) - timedelta(days=730)).strftime("%Y%m%d")
    base = "%s?url=%s&matchType=exact&output=json&fl=timestamp,digest&filter=statuscode:200" % (CDX, host)
    queries = {"first": base + "&limit=1", "latest": base + "&limit=-1", "recent": base + "&collapse=digest&from=%s&limit=%d" % (since, CAP)}
    get = rows or (lambda kind: _rows(queries[kind]))
    out = []

    first, why = get("first")
    if first is None:
        out.append(unknown("wayback_first", S, "First archived", "The Wayback Machine did not answer (%s)." % why, source=src, verify=verify))
    elif first:
        d = _when(first[0][0])
        out.append(check("wayback_first", S, "First archived", "info", value=d.isoformat() if d else first[0][0], priority=93,
                         detail="The earliest recorded version of the home page. The site is at least this old.", source=src, verify=verify))
    else:
        out.append(check("wayback_first", S, "First archived", "info", value="never archived", priority=93,
                         detail="The archive holds no copy of this address, which is common for small sites it has not visited.", source=src, verify=verify))

    recent, why = get("recent")
    latest, _ = get("latest")
    last = _when(latest[0][0]) if latest else None
    if recent is None:
        out.append(unknown("wayback_changes", S, "Home page changes (last 24 months)", "The Wayback Machine did not answer (%s)." % why, source=src, verify=verify))
    elif not recent:
        out.append(check("wayback_changes", S, "Home page changes (last 24 months)", "info", value="no snapshots", priority=94,
                         detail="The archive recorded no version of the home page in the last 24 months. That usually means it did not visit, not that nothing changed.", source=src, verify=verify))
    else:
        n = "%d+" % CAP if len(recent) >= CAP else str(len(recent))
        tail = (", the most recent snapshot on %s" % last.isoformat()) if last else ""
        out.append(check("wayback_changes", S, "Home page changes (last 24 months)", "info", value="%s different version(s)%s" % (n, ("; latest " + last.isoformat()) if last else ""), priority=94,
                         detail="The archive saw %s distinct versions of the home page in the last 24 months%s. It only records when it visits, so the real number of edits may be higher." % (n, tail),
                         source=src, verify=verify))
    return out

"""raptor/audit/compare.py: "Competitor comparison": the same measures on the company and up to 3 competitors, in one table.

The competitors are the ones the person entered (nothing is guessed). Each is read with the same checks as the company (the light versions: no
crawl), on the same day. A competitor whose site refuses us gets "couldn't check" in those cells, never a zero. Search positions come from the
searches already run for the company's own rankings, so they cost nothing extra.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from . import domain, funnel, site as site_checks
from .common import now_iso, registrable

log = logging.getLogger("raptor_audit_compare")

COLUMNS = [("https_works", "Secure (HTTPS)"), ("http_redirect", "http goes to https"), ("spf", "SPF"), ("dmarc", "DMARC"), ("viewport", "Mobile viewport"),
           ("meta_description", "Search description"), ("structured_data", "Structured data"), ("security_headers", "Security headers"),
           ("contact_path", "A way to contact"), ("whatsapp_button", "WhatsApp contact"), ("analytics", "Visitor tracking")]


def profile(site: dict) -> dict:
    """check id -> check, for one site, using the light checks."""
    checks, ctx = site_checks.run(site, light=True)
    if any(c["id"] == "site_reachable" for c in checks):
        # No website to read (the address does not lead anywhere, or did not answer): empty DNS records for a name like that say nothing useful.
        return {c["id"]: c for c in checks}
    checks = list(checks) + list(domain.run(site, light=True)) + (list(funnel.run(ctx)) if ctx is not None else [])
    return {c["id"]: c for c in checks}


def _cell(c):
    if c is None:
        return {"status": "unknown", "value": None}
    return {"status": c["status"], "value": c["value"]}


def build(inputs: dict, company_checks: dict, rankings: list, profile_fn=None) -> dict:
    """-> the comparison table for the report. company_checks: id -> check, already measured for the company."""
    profile_fn = profile_fn or profile
    comps = inputs.get("competitors", [])
    rows = [{"name": inputs["company"], "host": inputs["site"]["host"], "is_company": True,
             "cells": {cid: _cell(company_checks.get(cid)) for cid, _ in COLUMNS}}]

    def one(c):
        try:
            got = profile_fn(c)
            gone = got.get("site_reachable")
            return {"name": c["host"], "host": c["host"], "is_company": False, "note": (gone["detail"] if gone else None),
                    "cells": {cid: _cell(got.get(cid)) for cid, _ in COLUMNS}}
        except Exception:
            log.exception("competitor %s failed", c["host"])
            return {"name": c["host"], "host": c["host"], "is_company": False, "note": "This site could not be read.", "cells": {cid: {"status": "unknown", "value": None} for cid, _ in COLUMNS}}

    if comps:
        with ThreadPoolExecutor(max_workers=3) as pool:
            rows += list(pool.map(one, comps))

    queries = [r for r in rankings if r.get("kind") == "keyword"] or [r for r in rankings if r.get("kind") == "brand"]
    for row in rows:
        reg = registrable(row["host"])
        row["ranks"] = {q["query"]: (q.get("positions") or {}).get(reg) for q in queries}
    return {"columns": [{"id": cid, "title": title} for cid, title in COLUMNS], "rows": rows, "queries": [q["query"] for q in queries],
            "searched_from": next((q.get("location") for q in queries if q.get("location")), None), "date": queries[0]["date"] if queries else None,
            "generated_at": now_iso(),
            "note": "Same measures, same day, for every row. A '?' means that part could not be checked (for example the site blocks automated visits); it is never counted against a company."}

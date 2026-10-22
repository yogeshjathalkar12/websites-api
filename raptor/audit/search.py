"""raptor/audit/search.py: "Local visibility": where the company shows up when a customer searches, who pays for ads on those searches, its Google
reviews, and recent news. Read from Google's own results through SerpAPI (the key lives on this server: SERPAPI_KEY).

What is promised, and how:
  - A ranking is a snapshot. Every one records the exact search, the place it was searched from, and the date, and the report says so.
  - Only searches the person asked for are run (up to 5 keywords), plus the company's own name. Nothing is invented.
  - A review rating is shown only when the Google listing is matched with confidence (its website is the company's website). A match by name
    alone is labelled "please confirm". No match means nothing is shown.
  - Competitors' positions and advertisers come out of the same searches (no extra cost).
A search that fails or runs over today's audit quota is `unknown`, never a problem.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .common import check, registrable, unknown

log = logging.getLogger("raptor_audit_search")

S = "visibility"
SERPAPI_URL = "https://serpapi.com/search.json"
RESULTS = 20                       # how deep a ranking is read ("not in the top 20")
DAILY_QUOTA = int(os.getenv("AUDIT_SEARCHES_PER_DAY", "300"))      # all audits together, so one busy day cannot use up the shared search plan

_quota = {"day": None, "used": 0}
_quota_lock = threading.Lock()


class SearchUnavailable(Exception):
    pass


def _take_quota() -> bool:
    today = datetime.now(timezone.utc).date().isoformat()
    with _quota_lock:
        if _quota["day"] != today:
            _quota["day"], _quota["used"] = today, 0
        if _quota["used"] >= DAILY_QUOTA:
            return False
        _quota["used"] += 1
        return True


def _serp(params: dict) -> dict:
    """One SerpAPI search. Raises SearchUnavailable with a plain-words reason."""
    key = os.getenv("SERPAPI_KEY")
    if not key:
        raise SearchUnavailable("Search is not set up on the server yet.")
    if not _take_quota():
        raise SearchUnavailable("Today's audit search allowance has been used up. It resets tomorrow.")
    try:
        r = httpx.get(SERPAPI_URL, params={**params, "api_key": key}, timeout=30.0)
    except httpx.HTTPError as e:
        raise SearchUnavailable("The search service did not answer (%s)." % type(e).__name__)
    if r.status_code != 200:
        raise SearchUnavailable("The search service answered HTTP %d." % r.status_code)
    data = r.json()
    if data.get("error") and "hasn't returned any results" not in data["error"].lower() and "no results" not in data["error"].lower():
        raise SearchUnavailable("The search service said: %s" % str(data["error"])[:120])
    return data


def _host(link: str) -> str:
    try:
        return (urlparse(link or "").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def _places(data: dict) -> list:
    lr = data.get("local_results")
    if isinstance(lr, dict):
        lr = lr.get("places")
    return lr if isinstance(lr, list) else []


def analyse(data: dict, reg: str, company: str) -> dict:
    """Pulls the facts out of one Google result page: the company's position, the top results, the map pack, and the advertisers."""
    organic = data.get("organic_results") or []
    top, position, positions = [], None, {}
    for i, item in enumerate(organic[:RESULTS], 1):
        host = _host(item.get("link"))
        pos = item.get("position") or i
        if host:
            positions.setdefault(registrable(host), pos)
        if host and registrable(host) == reg and position is None:
            position = pos
        if len(top) < 10:
            top.append({"position": pos, "domain": host, "title": (item.get("title") or "")[:100]})
    pack, pack_pos = [], None
    for i, place in enumerate(_places(data)[:6], 1):
        host = _host(place.get("website") or place.get("link"))
        pack.append({"position": i, "title": (place.get("title") or "")[:80], "domain": host, "rating": place.get("rating"), "reviews": place.get("reviews")})
        if pack_pos is None and ((host and registrable(host) == reg) or (_norm(place.get("title")) and _norm(place.get("title")) == _norm(company))):
            pack_pos = i
    advertisers = []
    for ad in data.get("ads") or []:
        host = _host(ad.get("link") or ad.get("displayed_link") or "")
        if host and host not in advertisers:
            advertisers.append(host)
    return {"position": position, "positions": positions, "top": top, "map_pack": pack, "map_position": pack_pos, "advertisers": advertisers,
            "own_ad": any(registrable(a) == reg for a in advertisers)}


def _reviews(company: str, city: str, reg: str, serp):
    """(check). Uses Google Maps results for 'company city'; accepted only on a website match, or flagged when matched by exact name."""
    q = ("%s %s" % (company, city or "")).strip()
    try:
        data = serp({"engine": "google_maps", "type": "search", "q": q})
    except SearchUnavailable as e:
        return unknown("google_reviews", S, "Google reviews", str(e), source="Google Maps results via SerpAPI")
    candidates = []
    if isinstance(data.get("place_results"), dict):
        candidates.append(data["place_results"])
    candidates += [p for p in (data.get("local_results") or []) if isinstance(p, dict)]
    exact = [p for p in candidates if (p.get("website") and registrable(_host(p["website"])) == reg)]
    how, match = "website", (exact[0] if exact else None)
    if match is None:
        named = [p for p in candidates if _norm(p.get("title")) == _norm(company)]
        if len(named) == 1:
            how, match = "name", named[0]
    if match is None or match.get("rating") is None:
        return unknown("google_reviews", S, "Google reviews", "No Google Maps listing could be matched to this company with confidence, so no rating is shown.",
                       source="Google Maps results via SerpAPI for '%s'" % q, verify="Search the company on Google Maps and read its rating.")
    rating, count = float(match["rating"]), int(match.get("reviews") or 0)
    status = "pass" if rating >= 4.0 and count >= 20 else "issue" if rating < 3.5 else "warn"
    why = []
    if rating < 4.0:
        why.append("a rating under 4.0 puts off many customers")
    if count < 20:
        why.append("only %d review%s, which is few for customers to trust" % (count, "" if count == 1 else "s"))
    return check("google_reviews", S, "Google reviews", status, value="%.1f stars from %d review%s" % (rating, count, "" if count == 1 else "s"), weight=2 if status != "pass" else 1, priority=36,
                 detail=("Matched by its website. " if how == "website" else "Matched by exact name only, so please confirm this is the right listing. ") + ("; ".join(why).capitalize() + "." if why else "A healthy rating and enough reviews."),
                 source="Google Maps listing '%s' via SerpAPI" % (match.get("title") or q), verify="Search '%s' on Google Maps and read the rating." % q,
                 fix="" if status == "pass" else "Ask happy customers for Google reviews and reply to every review.",
                 raptor="Raptor's follow-up sequences can ask for a Google review after a sale." if status != "pass" else "",
                 evidence={"place": match.get("title"), "rating": rating, "reviews": count, "matched_by": how})


def _news(company: str, serp):
    try:
        data = serp({"engine": "google_news", "q": '"%s"' % company})
    except SearchUnavailable as e:
        return unknown("news", S, "Recent news", str(e), source="Google News via SerpAPI")
    items = [n for n in (data.get("news_results") or []) if isinstance(n, dict)][:5]
    if not items:
        return check("news", S, "Recent news", "info", value="none found", priority=88, detail="No recent news articles naming the company were found.", source="Google News via SerpAPI",
                     verify="Search the company name on news.google.com.")
    lines = ["%s (%s%s)" % ((n.get("title") or "")[:90], (n.get("source") or {}).get("name") if isinstance(n.get("source"), dict) else n.get("source") or "", (", " + n["date"]) if n.get("date") else "") for n in items]
    return check("news", S, "Recent news", "info", value="%d article(s)" % len(items), priority=88, detail="; ".join(lines), source="Google News via SerpAPI", verify="Search the company name on news.google.com.",
                 evidence=[{"title": n.get("title"), "link": n.get("link"), "date": n.get("date")} for n in items])


def run(inputs: dict, serp=None):
    """-> (checks, rankings). `serp` lets tests stand in for the search service. rankings = one row per search, kept for the report's evidence table
    and the competitor comparison."""
    serp = serp or _serp
    site, company, city = inputs["site"], inputs["company"], inputs.get("city")
    reg = site["registrable"]
    when = datetime.now(timezone.utc).strftime("%d %b %Y")
    where = city or "no place set (Google's default for the server)"
    out, rankings = [], []

    searches = [("brand", company)] + [("keyword", k) for k in inputs.get("keywords", [])[:5]]
    reason = None
    for kind, query in searches:
        if reason:
            break
        params = {"engine": "google", "q": query, "num": RESULTS}
        if city:
            params["location"] = city
        try:
            data = serp(params)
        except SearchUnavailable as e:
            reason = str(e)
            break
        info = analyse(data, reg, company)
        info.update({"query": query, "kind": kind, "location": city, "date": when})
        rankings.append(info)

    scope = "Searched on Google for '%s' from %s on %s. Rankings change by place and day."
    for row in rankings:
        pos = row["position"]
        rival = ", ".join("#%d %s" % (t["position"], t["domain"]) for t in row["top"][:5] if registrable(t["domain"]) != reg and t["domain"])
        pack = (" In the map pack: #%d." % row["map_position"]) if row["map_position"] else (" Not in the map pack." if row["map_pack"] else "")
        detail = scope % (row["query"], where, when) + pack + (" Top results: " + rival + "." if rival else "")
        verify = "Search Google for '%s'%s." % (row["query"], (" with your location set to " + city) if city else "")
        if row["kind"] == "brand":
            status = "pass" if pos == 1 else "warn" if pos and pos <= 5 else "issue" if pos is None else "warn"
            out.append(check("rank_brand", S, "Found when searching its own name", status, value=("#%d" % pos) if pos else "not in the top %d" % RESULTS, weight=2, priority=34,
                             detail=detail, source="Google results via SerpAPI", verify=verify, fix="" if status == "pass" else "Make sure the website, Google Business Profile and social pages use the exact company name.", evidence=row))
        else:
            status = "pass" if pos and pos <= 3 else "warn" if pos and pos <= 10 else "warn" if pos else "issue"
            out.append(check("rank_" + _norm(row["query"]).replace(" ", "_")[:40], S, "Ranking for '%s'" % row["query"], status, value=("#%d" % pos) if pos else "not in the top %d" % RESULTS, weight=2 if status == "issue" else 1,
                             priority=35, detail=detail, source="Google results via SerpAPI", verify=verify,
                             fix="" if status == "pass" else "Create a page that answers this search and earn local links and reviews.", evidence=row))

    if rankings:
        n_ads = [r for r in rankings if r["advertisers"]]
        others = sorted({a for r in rankings for a in r["advertisers"] if registrable(a) != reg})
        own = [r["query"] for r in rankings if r["own_ad"]]
        out.append(check("search_ads", S, "Paid search ads on these searches", "info", priority=89,
                         value="ads on %d of %d searches" % (len(n_ads), len(rankings)),
                         detail=("Advertisers paying to appear: %s. " % ", ".join(others[:8]) if others else "No paid ads were shown on these searches. ") +
                                ("This company's own ads appeared for: %s." % ", ".join(own) if own else "No ads from this company were seen.") + " Ads change by hour; this is a snapshot from %s." % when,
                         source="Google results via SerpAPI", verify="Search the same phrases on Google and look for results marked 'Sponsored'.", evidence=[{"query": r["query"], "advertisers": r["advertisers"]} for r in rankings]))
    elif reason:
        out.append(unknown("rank_brand", S, "Search rankings", reason, source="Google results via SerpAPI"))
    if not inputs.get("keywords") and rankings:
        out.append(check("keywords_hint", S, "Search keywords", "info", value="none entered", priority=95,
                         detail="Only the company's own name was searched. Enter up to 5 phrases customers would search (for example 'warehouse robots Pune') to see how it ranks for them.", source="Audit inputs"))

    out.append(_reviews(company, city, reg, serp))
    out.append(_news(company, serp))
    return out, rankings

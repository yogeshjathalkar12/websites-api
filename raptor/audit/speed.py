"""raptor/audit/speed.py: speed, page weight and automated accessibility, from Google's own PageSpeed Insights API (Lighthouse).

Two different things are reported separately and labelled: the LAB result (a simulated phone loading the page once, which varies a few points
between runs) and the FIELD result (what real Chrome visitors experienced over the last 28 days, which Google only has for sites with enough
traffic). Accessibility is "automated checks only": it finds common problems and does not replace a human review.
Optional environment variable GOOGLE_PAGESPEED_API_KEY raises Google's quota; without it the shared free quota is used and a busy answer is `unknown`.
"""
from __future__ import annotations

import os

import httpx

from .common import check, unknown

S = "website"
API = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
FIELD = {"FAST": "pass", "AVERAGE": "warn", "SLOW": "issue"}


def _ms(audits: dict, key: str):
    a = audits.get(key) or {}
    return a.get("numericValue"), a.get("displayValue") or ""


def run(url: str, call=None):
    """-> list of checks. `call` lets tests supply Google's answer (a dict) instead of the network."""
    verify = "Open pagespeed.web.dev, paste %s, choose Mobile (lab scores move a few points between runs)." % url
    src = "Google PageSpeed Insights API (Lighthouse), mobile"
    data = None
    if call is not None:
        data = call(url)
    else:
        params = [("url", url), ("strategy", "mobile"), ("category", "performance"), ("category", "accessibility")]
        key = os.getenv("GOOGLE_PAGESPEED_API_KEY")
        if key:
            params.append(("key", key))
        why = ""
        for attempt in range(2):
            try:
                r = httpx.get(API, params=params, timeout=75.0)
                if r.status_code == 200:
                    data = r.json()
                    break
                why = "Google's speed test answered HTTP %d%s." % (r.status_code, " (its free quota is busy)" if r.status_code == 429 else "")
                if r.status_code in (400, 404, 429):
                    break
            except httpx.TimeoutException:
                why = "Google's speed test took too long."
            except Exception as e:
                why = "Google's speed test could not be reached (%s)." % type(e).__name__
        if data is None:
            return [unknown("speed_lab", S, "Mobile speed", why or "Google's speed test did not answer.", source=src, verify=verify),
                    unknown("page_weight", S, "Total page weight", why or "Google's speed test did not answer.", source=src)]

    lh = data.get("lighthouseResult") or {}
    if lh.get("runtimeError") or not lh.get("categories"):
        reason = (lh.get("runtimeError") or {}).get("message") or "Google could not load the page for its test."
        return [unknown("speed_lab", S, "Mobile speed", reason[:200], source=src, verify=verify), unknown("page_weight", S, "Total page weight", reason[:200], source=src)]
    audits, cats = lh.get("audits", {}), lh.get("categories", {})
    out = []

    perf = cats.get("performance", {}).get("score")
    if perf is not None:
        score = round(perf * 100)
        lcp, lcp_txt = _ms(audits, "largest-contentful-paint")
        tbt, tbt_txt = _ms(audits, "total-blocking-time")
        cls, cls_txt = _ms(audits, "cumulative-layout-shift")
        status = "pass" if score >= 90 else "warn" if score >= 50 else "issue"
        out.append(check("speed_lab", S, "Mobile speed (lab test)", status, value="%d / 100" % score, weight=3 if status == "issue" else 2, priority=31,
                         detail="Simulated mid-range phone on a slow connection. Main content appears after %s; blocking time %s; layout shift %s. Lab results vary a few points between runs." % (lcp_txt or "n/a", tbt_txt or "n/a", cls_txt or "n/a"),
                         source=src, verify=verify, fix="" if status == "pass" else "Compress images, remove unused scripts, and use caching or a CDN.",
                         evidence={"score": score, "lcp_ms": lcp, "tbt_ms": tbt, "cls": cls, "fetched": lh.get("fetchTime"), "lighthouse": lh.get("lighthouseVersion")}))
    else:
        out.append(unknown("speed_lab", S, "Mobile speed (lab test)", "Google returned no performance score for this page.", source=src, verify=verify))

    field = data.get("loadingExperience") or {}
    category = field.get("overall_category")
    if category in FIELD:
        lcp_f = (field.get("metrics", {}).get("LARGEST_CONTENTFUL_PAINT_MS") or {}).get("percentile")
        out.append(check("speed_field", S, "Speed for real visitors", FIELD[category], value=category.title() + (" (main content in %.1f s)" % (lcp_f / 1000) if lcp_f else ""), weight=2, priority=32,
                         detail="Measured from real Chrome users who visited this page over the last 28 days (Chrome User Experience Report).", source="Google Chrome User Experience Report via PageSpeed Insights",
                         verify="Open pagespeed.web.dev for this address and read 'Discover what your real users are experiencing'.", fix="" if category == "FAST" else "Fix the slowest items listed in the lab test."))
    else:
        out.append(unknown("speed_field", S, "Speed for real visitors", "Google does not have enough real-visitor data for this page to publish a result (small sites often fall below its threshold).", source="Google Chrome User Experience Report"))

    weight, _ = _ms(audits, "total-byte-weight")
    if weight:
        mb = weight / 1_000_000
        status = "pass" if mb < 2.5 else "warn" if mb < 5 else "issue"
        out.append(check("page_weight", S, "Total page weight", status, value="%.1f MB" % mb, weight=1, priority=33,
                         detail="Everything a phone downloads to show the home page (images, scripts, styles). Heavy pages cost mobile data and load slowly.", source=src, verify=verify,
                         fix="" if status == "pass" else "Compress and resize images; remove scripts the page does not need."))
    else:
        out.append(unknown("page_weight", S, "Total page weight", "Google did not report the page weight.", source=src))

    acc = cats.get("accessibility", {}).get("score")
    if acc is not None:
        failed = []
        for aid, a in audits.items():
            if a.get("score") == 0 and a.get("scoreDisplayMode") == "binary" and aid in ("image-alt", "color-contrast", "label", "button-name", "link-name", "html-has-lang", "meta-viewport", "document-title", "frame-title"):
                n = len((a.get("details") or {}).get("items", []))
                failed.append("%s (%d element%s)" % (a.get("title", aid).rstrip("."), n, "" if n == 1 else "s"))
        score = round(acc * 100)
        status = "pass" if score >= 90 else "warn" if score >= 50 else "issue"
        out.append(check("accessibility", S, "Accessibility (automated checks)", status, value="%d / 100" % score, priority=49,
                         detail=("Automated checks only; they find common problems and do not replace a manual review. " + ("Found: " + "; ".join(failed[:6]) + "." if failed else "")), source="Lighthouse accessibility audit via PageSpeed Insights",
                         verify="Open pagespeed.web.dev for this address and read the Accessibility section.", fix="" if status == "pass" else "Add descriptions to images, label form fields, and raise text contrast."))
    return out

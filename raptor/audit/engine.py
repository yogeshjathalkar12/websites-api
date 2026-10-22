"""raptor/audit/engine.py: runs the audit sections in parallel, keeps each audit as a job the page can poll, and builds the finished report.

Jobs live in memory (this server restarts now and then; the page keeps the finished report, and an audit takes about a minute to run again).
At most MAX_RUNNING audits run at once so the server stays responsive; each person is limited per day.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import compare, domain, funnel, history, search, site as site_checks, speed
from .common import PRIORITY_RULE, SECTIONS, now_iso, ordered_problems, score, unknown

log = logging.getLogger("raptor_audit")

MAX_RUNNING = 2
PER_USER_RUNNING = 1
PER_USER_PER_DAY = 15
JOB_TTL = 3 * 3600
JOB_DEADLINE = 200

PRESETS = {
    "general": ("Any company", ["website", "domain_email", "funnel", "visibility", "history"]),
    "local": ("Local service or retail", ["visibility", "funnel", "website", "domain_email", "history"]),
    "b2b": ("B2B or manufacturer", ["domain_email", "funnel", "website", "visibility", "history"]),
    "online": ("SaaS or online business", ["website", "funnel", "domain_email", "visibility", "history"]),
}

JOBS: dict = {}
_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_RUNNING)
_history: dict = {}            # user id -> start times


class Refused(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


def _purge(now: float):
    for jid in [j for j, v in JOBS.items() if now - v["created"] > JOB_TTL]:
        JOBS.pop(jid, None)


def start(user_id: str, inputs: dict, runner=None) -> str:
    """Registers a job and starts it in the background. Raises Refused when this person has used up their limits."""
    now = time.time()
    with _lock:
        _purge(now)
        recent = [t for t in _history.get(user_id, []) if now - t < 86400]
        if len(recent) >= PER_USER_PER_DAY:
            raise Refused(429, "You have run %d audits in the last 24 hours, which is the daily limit. It resets within a day." % PER_USER_PER_DAY)
        if sum(1 for j in JOBS.values() if j["user"] == user_id and j["status"] == "running") >= PER_USER_RUNNING:
            raise Refused(429, "An audit of yours is still running. Wait for it to finish before starting another.")
        recent.append(now)
        _history[user_id] = recent
        jid = uuid.uuid4().hex[:16]
        JOBS[jid] = {"id": jid, "user": user_id, "created": now, "status": "running", "inputs": inputs, "sections": {}, "progress": [], "report": None, "error": None}
    threading.Thread(target=_run, args=(jid, runner or _default_runner), daemon=True).start()
    return jid


def public_view(job: dict) -> dict:
    return {"id": job["id"], "status": job["status"], "progress": job["progress"], "report": job["report"], "error": job["error"],
            "sections_done": {k: v for k, v in job["sections"].items()}}


def get(user_id: str, jid: str):
    job = JOBS.get(jid)
    if not job or job["user"] != user_id:
        return None
    return public_view(job)


def _note(job: dict, text: str):
    job["progress"].append({"at": now_iso(), "text": text})


def _default_runner(job: dict):
    """Runs every section; returns ({section id: [checks]}, {extras}). Each part is guarded so one failing part never loses the rest."""
    inputs = job["inputs"]
    site = inputs["site"]
    results: dict = {}
    extras: dict = {}

    def guard(name, fn, section, *args):
        try:
            _note(job, "Checking " + name)
            return fn(*args)
        except Exception as e:             # a bug or an odd site must not lose the other sections
            log.exception("audit part %s failed", name)
            return [unknown(name.replace(" ", "_"), section, name.capitalize(), "This part could not be completed (%s)." % type(e).__name__)]

    def visibility():
        try:
            _note(job, "Searching Google")
            return search.run(inputs)
        except Exception as e:
            log.exception("audit search part failed")
            return [unknown("rank_brand", "visibility", "Search rankings", "This part could not be completed (%s)." % type(e).__name__)], []

    with ThreadPoolExecutor(max_workers=8) as pool:
        f_speed = pool.submit(guard, "mobile speed", speed.run, "website", site["start_url"])
        f_domain = pool.submit(guard, "domain and email", domain.run, "domain_email", site)
        f_search = pool.submit(visibility)
        f_history = pool.submit(guard, "site history", history.run, "history", site)
        try:
            _note(job, "Reading the website")
            site_list, ctx = site_checks.run(site)
        except Exception as e:
            log.exception("audit site part failed")
            site_list, ctx = [unknown("website_read", "website", "Website", "The website could not be read (%s)." % type(e).__name__)], None
        results["website"] = list(site_list)
        job["sections"]["website"] = {"done": False, "checks": results["website"]}
        if ctx is not None:
            results["funnel"] = guard("funnel", funnel.run, "funnel", ctx)
        else:
            results["funnel"] = [unknown("funnel", "funnel", "Funnel", "The website could not be read.")]
        job["sections"]["funnel"] = {"done": True, "checks": results["funnel"]}
        results["domain_email"] = f_domain.result(timeout=JOB_DEADLINE)
        job["sections"]["domain_email"] = {"done": True, "checks": results["domain_email"]}
        try:
            results["website"] += f_speed.result(timeout=JOB_DEADLINE)
        except Exception:
            results["website"].append(unknown("speed_lab", "website", "Mobile speed", "The speed test did not finish in time."))
        job["sections"]["website"] = {"done": True, "checks": results["website"]}
        try:
            results["visibility"], rankings = f_search.result(timeout=JOB_DEADLINE)
        except Exception:
            results["visibility"], rankings = [unknown("rank_brand", "visibility", "Search rankings", "The searches did not finish in time.")], []
        job["sections"]["visibility"] = {"done": True, "checks": results["visibility"]}
        results["history"] = f_history.result(timeout=JOB_DEADLINE)
        job["sections"]["history"] = {"done": True, "checks": results["history"]}
        if inputs.get("competitors"):
            _note(job, "Comparing with competitors")
            mine = {c["id"]: c for sec in ("website", "domain_email", "funnel") for c in results[sec]}
            extras["competitors"] = compare.build(inputs, mine, rankings)
        extras["rankings"] = [{k: v for k, v in r.items() if k != "positions"} for r in rankings]
    return results, extras


def _run(jid: str, runner):
    job = JOBS.get(jid)
    if not job:
        return
    with _slots:
        try:
            got = runner(job)
            results, extras = got if isinstance(got, tuple) else (got, {})
            job["report"] = build_report(job["inputs"], results, extras)
            job["status"] = "done"
        except Exception as e:
            log.exception("audit failed")
            job["status"] = "error"
            job["error"] = "The audit could not be completed (%s). Try again in a minute." % type(e).__name__


def build_report(inputs: dict, results: dict, extras: dict = None) -> dict:
    preset = inputs.get("preset") if inputs.get("preset") in PRESETS else "general"
    order = PRESETS[preset][1]
    titles = dict(SECTIONS)
    sections, every = [], []
    for sid in order:
        checks = sorted(results.get(sid, []), key=lambda c: (c["priority"], c["id"]))
        if checks:
            sections.append({"id": sid, "title": titles[sid], "checks": checks})
            every += checks
    problems = ordered_problems(every)
    fixes = [c for c in problems if c.get("fix")][:5]
    return {
        "company": inputs.get("company"), "website": inputs["site"]["host"], "generated_at": now_iso(), "preset": preset, "preset_title": PRESETS[preset][0],
        "city": inputs.get("city"), "note": inputs.get("note"), "keywords": inputs.get("keywords", []),
        "score": score(every), "sections": sections,
        "top_findings": [{"id": c["id"], "title": c["title"], "status": c["status"], "value": c["value"], "detail": c["detail"]} for c in problems[:3]],
        "fixes": [{"id": c["id"], "title": c["title"], "status": c["status"], "fix": c["fix"], "raptor": c.get("raptor", "")} for c in fixes],
        "priority_rule": PRIORITY_RULE, "competitors": (extras or {}).get("competitors"), "rankings": (extras or {}).get("rankings", []),
        "counts": {s: sum(1 for c in every if c["status"] == s) for s in ("pass", "warn", "issue", "info", "unknown")},
    }

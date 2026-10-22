"""raptor/audit/common.py: the shape of one finding, and how a score is worked out from findings.

Status of a check:
  pass     measured, and fine
  warn     measured, and could be better (counts half in the score)
  issue    measured, and a real problem (counts zero)
  info     a measured fact that is neither good nor bad (never scored)
  unknown  we could NOT check it; the reason is in `detail` (never scored, never shown as a problem)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

STATUSES = ("pass", "warn", "issue", "info", "unknown")
SCORED = {"pass": 1.0, "warn": 0.5, "issue": 0.0}

SECTIONS = [
    ("website", "Website health"),
    ("domain_email", "Domain and email trust"),
    ("funnel", "Leaks in the funnel"),
    ("visibility", "Local visibility"),
    ("history", "Site history"),
]

# Fixed, published order for "what to fix first": lower number = earlier. Nobody's guess about impact, just a rule that is written down:
# security and email trust first (they put the company and its customers at risk), then ways customers can reach the company, then speed,
# then search basics, then the rest.
PRIORITY_RULE = ("Security and email trust first, then ways customers can reach you, then speed, then search basics, then the rest.")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(cid: str, section: str, title: str, status: str, *, value=None, detail: str = "", source: str = "", verify: str = "",
          weight: int = 1, priority: int = 60, fix: str = "", raptor: str = "", evidence=None) -> dict:
    assert status in STATUSES, status
    return {"id": cid, "section": section, "title": title, "status": status, "value": value, "detail": detail, "source": source,
            "verify": verify, "weight": weight, "priority": priority, "fix": fix, "raptor": raptor, "evidence": evidence, "checked_at": now_iso()}


def unknown(cid: str, section: str, title: str, reason: str, **kw) -> dict:
    return check(cid, section, title, "unknown", detail=reason, **kw)


def score(checks: list) -> dict:
    """The score is the weighted share of MEASURED checks (pass / warn / issue) that are fine. Unknown and info checks are left out, and the
    result always says how many checks it is based on."""
    scored = [c for c in checks if c["status"] in SCORED]
    total_weight = sum(c["weight"] for c in scored)
    value = None if total_weight == 0 else round(100 * sum(c["weight"] * SCORED[c["status"]] for c in scored) / total_weight)
    unknown_count = sum(1 for c in checks if c["status"] == "unknown")
    return {"value": value, "based_on": len(scored), "of": len(scored) + unknown_count, "unknown": unknown_count,
            "label": None if value is None else ("Strong" if value >= 80 else "Needs work" if value >= 50 else "Weak")}


def ordered_problems(checks: list) -> list:
    """Issues first, then warnings, each group by the fixed priority rule, then by weight."""
    problems = [c for c in checks if c["status"] in ("issue", "warn")]
    return sorted(problems, key=lambda c: (0 if c["status"] == "issue" else 1, c["priority"], -c["weight"], c["id"]))


# ---- small helpers used by several modules ----

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_TWO_PART_TLDS = {"co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "res.in", "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
                  "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "com.sg", "com.my", "com.pk", "com.bd", "com.lk", "com.np", "co.jp", "com.hk",
                  "com.cn", "com.tr", "com.mx", "com.ar", "co.id", "co.th", "co.ke", "co.ae", "com.sa", "com.eg", "com.ng"}


def normalize_site(raw: str) -> Optional[dict]:
    """'acme.com', 'www.acme.com/about' or 'https://acme.com' -> {host, registrable, start_url}; None if it is not a plain website address."""
    text = (raw or "").strip().lower()
    if not text or len(text) > 300 or " " in text:
        return None
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    host = text.split("/")[0].split("?")[0].split("#")[0].split("@")[-1]
    port = None
    if ":" in host:
        host, _, port = host.partition(":")
        if port not in ("", "80", "443"):
            return None
    host = host.strip(".")
    if not _DOMAIN.match(host):          # also rejects IP addresses and 'localhost'
        return None
    return {"host": host, "registrable": registrable(host), "start_url": "https://" + host + "/"}


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

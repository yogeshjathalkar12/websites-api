"""
diagnostic_router.py — Email deliverability & health checks

Three things, all on public DNS data (no mailbox access needed):
  POST /bulk-check    - for each domain: can it receive mail (MX), and has it
                        published the two records receiving servers look for to
                        trust its mail (SPF and DMARC)?
  POST /blacklist     - is the domain's mail server's IP on well-known spam
                        blocklists (DNSBLs)?
  POST /parse-headers - paste the raw headers of a bounced / delayed email and
                        get the route it took, hop by hop, with the biggest
                        delay highlighted.

Credits: charged only once there is an answer to give (a domain that doesn't
exist, a header block with no hops, or an unreachable DNS answer costs nothing).
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Body, Depends, HTTPException

from .raptor_auth import deduct_credit, get_current_user

try:
    import dns.exception
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - dnspython is in requirements.txt
    _DNS_AVAILABLE = False

router = APIRouter()

MAX_DOMAINS = 200
DNS_TIMEOUT = 3.0  # seconds, per lookup
DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "psbl.surriel.com",
    "dnsbl.sorbs.net",
]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _resolver() -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _clean_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0]
    if "@" in d:
        d = d.split("@")[-1]
    return d.strip(". ")


def _txt_records(resolver, name: str) -> list:
    try:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in resolver.resolve(name, "TXT")]
    except Exception:
        return []


def _mx_hosts(resolver, domain: str) -> list:
    answers = resolver.resolve(domain, "MX")
    return [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]


def _check_domain(domain: str) -> dict:
    resolver = _resolver()
    reasons = []
    try:
        mx = [h for h in _mx_hosts(resolver, domain) if h]
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "mx": [], "spf": False, "dmarc": False, "verdict": "fail", "reasons": ["This domain doesn't exist."]}
    except Exception:
        mx = []

    spf = any(t.lower().startswith("v=spf1") for t in _txt_records(resolver, domain))
    dmarc = any(t.lower().startswith("v=dmarc1") for t in _txt_records(resolver, f"_dmarc.{domain}"))

    if not mx:
        reasons.append("No mail server is set up for this domain, so it can't receive email.")
    if not spf:
        reasons.append("No SPF record: receiving servers can't confirm who is allowed to send as this domain.")
    if not dmarc:
        reasons.append("No DMARC record: nothing tells receivers what to do with fake mail from this domain.")

    verdict = "fail" if not mx else ("healthy" if spf and dmarc else "warn")
    return {"domain": domain, "mx": mx, "spf": spf, "dmarc": dmarc, "verdict": verdict, "reasons": reasons}


@router.get("/status")
def status():
    return {"tool": "deliverability-diagnostics", "status": "operational" if _DNS_AVAILABLE else "dns library missing"}


@router.post("/bulk-check")
def bulk_check(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    if not _DNS_AVAILABLE:
        raise HTTPException(status_code=503, detail="DNS checks aren't available on the server right now.")
    raw = payload.get("domains") or []
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=400, detail="Enter at least one domain.")
    if len(raw) > MAX_DOMAINS:
        raise HTTPException(status_code=400, detail=f"Check up to {MAX_DOMAINS} domains at a time.")

    seen, domains, invalid = set(), [], []
    for item in raw:
        d = _clean_domain(str(item))
        if not d or d in seen:
            continue
        seen.add(d)
        (domains if DOMAIN_RE.match(d) else invalid).append(d if d else str(item))
    if not domains:
        raise HTTPException(status_code=400, detail="None of those look like domains. Use something like acme.com.")

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_check_domain, domains))

    remaining = deduct_credit(user_id, amount=len(results))
    for bad in invalid:
        results.append({"domain": bad, "mx": [], "spf": False, "dmarc": False, "verdict": "fail", "reasons": ["That doesn't look like a domain."]})
    return {"results": results, "credits_left": remaining}


def _dnsbl_lookup(ip: str, zone: str):
    """True = listed, False = clean, None = couldn't tell (timeout, or the
    list refuses queries from shared servers)."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    resolver = _resolver()
    try:
        answers = resolver.resolve(f"{reversed_ip}.{zone}", "A")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return None
    codes = [str(a) for a in answers]
    # 127.255.255.x is how lists say "I won't answer this resolver" - not a listing.
    if any(c.startswith("127.255.255.") for c in codes):
        return None
    return any(c.startswith("127.") for c in codes)


@router.post("/blacklist")
def blacklist(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    if not _DNS_AVAILABLE:
        raise HTTPException(status_code=503, detail="DNS checks aren't available on the server right now.")
    domain = _clean_domain(str(payload.get("domain", "")))
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Enter a domain like acme.com.")

    resolver = _resolver()
    try:
        hosts = _mx_hosts(resolver, domain)
    except Exception:
        hosts = []
    if not hosts:
        return {"error": f"{domain} has no mail server to check, so there is nothing to look up on blocklists."}

    mx_host, ip = hosts[0], None
    for host in hosts:
        try:
            ip = str(resolver.resolve(host, "A")[0])
            mx_host = host
            break
        except Exception:
            continue
    if not ip:
        return {"error": f"Couldn't find the address of {domain}'s mail server ({hosts[0]})."}
    try:
        if ipaddress.ip_address(ip).version != 4:
            return {"error": "That mail server only has an IPv6 address, which these blocklists don't cover."}
    except ValueError:
        return {"error": "Couldn't read the mail server's address."}

    with ThreadPoolExecutor(max_workers=len(DNSBL_ZONES)) as pool:
        flags = list(pool.map(lambda z: _dnsbl_lookup(ip, z), DNSBL_ZONES))
    checks = [{"zone": z, "listed": f} for z, f in zip(DNSBL_ZONES, flags)]

    remaining = deduct_credit(user_id)
    return {
        "mx_host": mx_host,
        "ip": ip,
        "listed_count": sum(1 for c in checks if c["listed"] is True),
        "checks": checks,
        "credits_left": remaining,
    }


_RECEIVED_SPLIT = re.compile(r"(?im)^received:\s*")
_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.I)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.I)
_IP_RE = re.compile(r"[\[(]((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,39})[\])]", re.I)


def _unfold(raw: str) -> str:
    # Header lines that continue on the next line start with whitespace.
    return re.sub(r"\r?\n[ \t]+", " ", raw)


def _parse_received(raw: str) -> list:
    text = _unfold(raw)
    chunks = _RECEIVED_SPLIT.split(text)[1:]
    hops = []
    for chunk in chunks:
        line = chunk.split("\n")[0].strip()
        stamp_text = line.rsplit(";", 1)[1].strip() if ";" in line else ""
        try:
            when = parsedate_to_datetime(stamp_text) if stamp_text else None
        except Exception:
            when = None
        m_from, m_by, m_ip = _FROM_RE.search(line), _BY_RE.search(line), _IP_RE.search(line)
        hops.append({
            "from_host": m_from.group(1).strip("();") if m_from else None,
            "by_host": m_by.group(1).strip("();") if m_by else None,
            "ip": m_ip.group(1) if m_ip else None,
            "timestamp": when.isoformat() if when else (stamp_text or None),
            "_when": when,
        })
    hops.reverse()  # headers list the newest hop first; show the journey in order
    return hops


@router.post("/parse-headers")
def parse_headers(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    raw = payload.get("raw_headers") or ""
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Paste the email's full headers first.")
    if len(raw) > 200_000:
        raise HTTPException(status_code=400, detail="That's too much text. Paste just the header block.")

    hops = _parse_received(raw)
    if not hops:
        return {"hop_count": 0, "hops": [], "likely_filter_hop": None, "likely_filter_index": None}

    slowest_idx, slowest = None, 0.0
    for i in range(1, len(hops)):
        a, b = hops[i - 1]["_when"], hops[i]["_when"]
        if a and b:
            try:
                gap = (b - a).total_seconds()
            except TypeError:
                continue
            hops[i]["delay_seconds"] = gap
            if gap > slowest:
                slowest, slowest_idx = gap, i
    if slowest < 60:  # a normal handover takes seconds; only call out a real wait
        slowest_idx = None

    clean = [{k: v for k, v in h.items() if k != "_when"} for h in hops]
    remaining = deduct_credit(user_id)
    return {
        "hop_count": len(clean),
        "hops": clean,
        "likely_filter_hop": clean[slowest_idx] if slowest_idx is not None else None,
        "likely_filter_index": slowest_idx,
        "credits_left": remaining,
    }

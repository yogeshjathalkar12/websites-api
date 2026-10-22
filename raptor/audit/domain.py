"""raptor/audit/domain.py: "Domain and email trust": the registration record (RDAP) and the mail DNS records (MX, SPF, DKIM, DMARC).

Read from public sources only (the domain registry's own RDAP service and public DNS). A DNS answer of "no such record" is a measured fact;
a timeout is `unknown`. DKIM lives under a name only the sender knows, so "not found" there is information, never a problem.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

try:
    import dns.exception
    import dns.resolver
    _DNS = True
except ImportError:  # pragma: no cover - dnspython is in requirements.txt
    _DNS = False

from . import fetcher
from .common import check, unknown

S = "domain_email"
DNS_TIMEOUT = 3.0
# The names the common providers use for their DKIM key (same list as the Deliverability Diagnostics tool).
DKIM_SELECTORS = ["zmail", "google", "selector1", "selector2", "resend", "default", "s1", "s2", "k1", "k2", "k3", "mandrill", "mail", "dkim", "smtp", "zoho",
                  "fm1", "fm2", "fm3", "protonmail", "mxvault", "titan", "dkim1", "everlytickey1"]
MAIL_PROVIDERS = [("Google Workspace", ("aspmx.l.google.com", "googlemail.com", ".google.com")), ("Microsoft 365", ("mail.protection.outlook.com",)),
                  ("Zoho Mail", ("zoho.com", "zoho.in", "zohomail")), ("Proton Mail", ("protonmail.ch",)), ("Titan Email", ("titan.email",)),
                  ("GoDaddy Email", ("secureserver.net",)), ("Yahoo Mail", ("yahoodns.net",)), ("Mimecast", ("mimecast.com",)), ("Rediffmail", ("rediffmail.com",)),
                  ("Hostinger Email", ("hostinger.com",)), ("Namecheap Private Email", ("privateemail.com", "registrar-servers.com")), ("Fastmail", ("messagingengine.com",))]


def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _txt(name: str):
    """List of TXT strings; [] if the name has no TXT record (a measured fact); None if the lookup itself failed (unknown)."""
    try:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in _resolver().resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return None


def _mx(domain: str):
    try:
        answers = _resolver().resolve(domain, "MX")
        return [str(r.exchange).rstrip(".").lower() for r in sorted(answers, key=lambda x: x.preference) if str(r.exchange).rstrip(".")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return None


def _spf_lookup_count(domain: str, depth: int = 0, budget=None):
    """(number of DNS-lookup terms, ok). SPF allows at most 10; more and receivers may ignore the record."""
    budget = budget if budget is not None else {"queries": 0}
    if depth > 6 or budget["queries"] > 20:
        return 0, False
    budget["queries"] += 1
    records = _txt(domain)
    if records is None:
        return 0, False
    spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
    if spf is None:
        return 0, True
    count, ok = 0, True
    for term in spf.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:") or t.startswith("redirect="):
            count += 1
            n, sub_ok = _spf_lookup_count(t.split(":", 1)[-1].split("=", 1)[-1], depth + 1, budget)
            count += n
            ok = ok and sub_ok
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count, ok


def _provider(mx_hosts: list):
    for name, needles in MAIL_PROVIDERS:
        if any(any(n in h for n in needles) for h in mx_hosts):
            return name
    return None


def _rdap(domain: str):
    res = fetcher.fetch("https://rdap.org/domain/%s" % domain, max_bytes=400_000, timeout=12, headers={"Accept": "application/rdap+json, application/json"})
    if res.error or res.status != 200:
        return None, ("this domain ending does not publish registration data" if (not res.error and res.status == 404) else "the registry did not answer (%s)" % (res.error_detail or res.status))
    try:
        return json.loads(res.body), ""
    except ValueError:
        return None, "the registry's answer could not be read"


def _date(text: str):
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def run(site: dict, light: bool = False):
    """-> list of checks. `site` comes from common.normalize_site. `light` skips the registration record, the SPF lookup count and DKIM (used for competitors)."""
    domain = site["registrable"]
    out = []
    verify_rdap = "Look the domain up at lookup.icann.org or the registry's own WHOIS page."

    # ---- registration record ----
    data, why = (None, "skipped") if light else _rdap(domain)
    if light:
        pass
    elif data is None:
        out.append(unknown("domain_expiry", S, "Domain expiry", "Could not read the registration record: %s." % why, source="RDAP via rdap.org"))
    else:
        events = {e.get("eventAction"): _date(e.get("eventDate", "")) for e in data.get("events", [])}
        registered, expires = events.get("registration"), events.get("expiration")
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        now = datetime.now(timezone.utc)
        if expires:
            days = (expires - now).days
            status = "issue" if days <= 30 else "warn" if days <= 90 else "pass"
            out.append(check("domain_expiry", S, "Domain expiry", status, value="%s (%d days left)" % (expires.date().isoformat(), days), weight=3 if status == "issue" else 2 if status == "warn" else 1, priority=7,
                             detail=("The domain expires in %d days. If it lapses, the website and every email address on it stop working." % days) if status != "pass" else "The domain is registered until %s." % expires.date().isoformat(),
                             source="RDAP record of %s (the registry's own data)" % domain, verify=verify_rdap, fix="Renew the domain now and switch on auto-renew." if status != "pass" else ""))
        else:
            out.append(unknown("domain_expiry", S, "Domain expiry", "The registry record does not show an expiry date.", source="RDAP record of %s" % domain))
        if registered:
            years = (now - registered).days / 365.25
            out.append(check("domain_age", S, "Domain age", "info", value="registered %s (%.1f years)" % (registered.date().isoformat(), years), priority=80,
                             detail="A long-held domain is a trust signal for search engines and customers." if years >= 3 else "", source="RDAP record of %s" % domain, verify=verify_rdap))
        if registrar:
            out.append(check("registrar", S, "Registrar", "info", value=registrar, priority=81, source="RDAP record of %s" % domain, verify=verify_rdap))

    if not _DNS:
        out.append(unknown("spf", S, "Email set-up", "DNS lookups are not available on this server."))
        return out

    # ---- mail ----
    mx_hosts = _mx(domain)
    if mx_hosts is None:
        out.append(unknown("mx", S, "Business email", "The DNS lookup for mail servers timed out. Try again.", source="DNS MX lookup of %s" % domain))
        mail_known = False
    else:
        mail_known = True
        if mx_hosts:
            provider = _provider(mx_hosts)
            out.append(check("mx", S, "Business email", "pass", value=provider or mx_hosts[0], weight=1, priority=12,
                             detail="Mail for this domain is handled by %s." % (provider or "the server " + mx_hosts[0]), source="DNS MX lookup of %s" % domain, verify="Run: nslookup -type=mx %s" % domain))
        else:
            out.append(check("mx", S, "Business email", "warn", value="no mail servers", weight=1, priority=12,
                             detail="No mail servers are set up for %s, so nobody can email an address on this domain." % domain, source="DNS MX lookup of %s" % domain,
                             verify="Run: nslookup -type=mx %s" % domain, fix="Set up business email on the domain."))

    txt = _txt(domain)
    if txt is None:
        out.append(unknown("spf", S, "SPF record", "The DNS lookup timed out. Try again.", source="DNS TXT lookup of %s" % domain))
    else:
        spfs = [t for t in txt if t.lower().startswith("v=spf1")]
        has_mail = bool(mx_hosts)
        if not spfs:
            out.append(check("spf", S, "SPF record", "issue" if has_mail else "warn", value="missing", weight=3 if has_mail else 1, priority=6,
                             detail="No SPF record: receiving servers cannot confirm who may send email as %s, so genuine mail is more likely to be treated as suspicious and anyone can pretend to be you." % domain,
                             source="DNS TXT lookup of %s" % domain, verify="Run: nslookup -type=txt %s  and look for v=spf1." % domain,
                             fix="Publish an SPF record listing the services that send your email.",
                             raptor="Raptor's free Deliverability Diagnostics tool re-checks SPF, DKIM and DMARC for any domain."))
        elif len(spfs) > 1:
            out.append(check("spf", S, "SPF record", "issue", value="%d SPF records" % len(spfs), weight=3, priority=6,
                             detail="A domain must have exactly one SPF record. With several, receivers treat SPF as broken.", source="DNS TXT lookup of %s" % domain,
                             verify="Run: nslookup -type=txt %s" % domain, fix="Merge them into one record."))
        else:
            rec = spfs[0]
            ending = re.search(r"([+\-~?]?)all\b", rec)
            q = ending.group(1) if ending else None
            if q == "+":
                out.append(check("spf", S, "SPF record", "issue", value="+all", weight=3, priority=6, detail="The record ends in +all, which allows anyone on the internet to send as this domain.",
                                 source="DNS TXT lookup of %s" % domain, verify="Run: nslookup -type=txt %s" % domain, fix="End the record with -all or ~all."))
            elif q is None or q == "?":
                out.append(check("spf", S, "SPF record", "warn", value=rec[:80], priority=6, detail="The record does not say what to do with mail from other senders (no -all or ~all at the end).",
                                 source="DNS TXT lookup of %s" % domain, verify="Run: nslookup -type=txt %s" % domain, fix="End the record with -all or ~all."))
            else:
                out.append(check("spf", S, "SPF record", "pass", value=rec[:80], priority=6, source="DNS TXT lookup of %s" % domain, verify="Run: nslookup -type=txt %s" % domain))
            n, ok = (0, False) if light else _spf_lookup_count(domain)
            if n > 10 and ok:
                out.append(check("spf_lookups", S, "SPF lookup limit", "issue", value="%d lookups (limit 10)" % n, weight=2, priority=8,
                                 detail="The SPF record needs %d DNS lookups; the standard allows 10, and above that many receivers ignore the whole record." % n, source="Recursive read of the SPF record of %s" % domain,
                                 verify="Paste the domain into an SPF checker such as dmarcian's SPF surveyor.", fix="Remove unused services from the record or flatten it."))
            elif ok:
                out.append(check("spf_lookups", S, "SPF lookup limit", "pass", value="%d of 10" % n, priority=8, source="Recursive read of the SPF record of %s" % domain))

    dm = _txt("_dmarc." + domain)
    if dm is None:
        out.append(unknown("dmarc", S, "DMARC record", "The DNS lookup timed out. Try again.", source="DNS TXT lookup of _dmarc.%s" % domain))
    else:
        rec = next((t for t in dm if t.lower().startswith("v=dmarc1")), None)
        if rec is None:
            out.append(check("dmarc", S, "DMARC record", "issue", value="missing", weight=3, priority=5,
                             detail="No DMARC record: nothing stops someone sending email that looks like it comes from %s, and nothing tells receiving servers what to do with it. "
                                    "Gmail and Yahoo also require DMARC from anyone sending more than 5,000 emails a day." % domain,
                             source="DNS TXT lookup of _dmarc.%s" % domain, verify="Run: nslookup -type=txt _dmarc.%s" % domain,
                             fix="Publish a DMARC record, start with p=none to watch, then move to quarantine or reject.",
                             raptor="Raptor's free Deliverability Diagnostics tool re-checks SPF, DKIM and DMARC for any domain."))
        else:
            policy = (re.search(r"\bp=\s*([a-z]+)", rec, re.I) or [None, ""])[1].lower()
            if policy in ("quarantine", "reject"):
                out.append(check("dmarc", S, "DMARC record", "pass", value="p=" + policy, priority=5, source="DNS TXT lookup of _dmarc.%s" % domain, verify="Run: nslookup -type=txt _dmarc.%s" % domain))
            else:
                out.append(check("dmarc", S, "DMARC record", "warn", value="p=%s" % (policy or "none"), weight=2, priority=5,
                                 detail="DMARC exists but is set to monitor only (p=none), so fake mail pretending to be you is still delivered.", source="DNS TXT lookup of _dmarc.%s" % domain,
                                 verify="Run: nslookup -type=txt _dmarc.%s" % domain, fix="After reviewing the reports, move the policy to quarantine, then reject."))

    if mail_known and mx_hosts and not light:
        found = []
        for selector in DKIM_SELECTORS:
            recs = _txt("%s._domainkey.%s" % (selector, domain)) or []
            if any(re.search(r"\bp=\s*[A-Za-z0-9+/=]+", r) for r in recs):
                found.append(selector)
        if found:
            out.append(check("dkim", S, "DKIM signing", "pass", value=", ".join(found), priority=9, source="DNS lookups of %d common selector names" % len(DKIM_SELECTORS),
                             verify="Run: nslookup -type=txt %s._domainkey.%s" % (found[0], domain)))
        else:
            out.append(check("dkim", S, "DKIM signing", "info", value="not found at %d common names" % len(DKIM_SELECTORS), priority=9,
                             detail="DKIM keys live under a name only the sender knows, so this does not prove DKIM is missing. Ask the email provider, or send a test email and read its headers.",
                             source="DNS lookups of %d common selector names" % len(DKIM_SELECTORS)))
    return out

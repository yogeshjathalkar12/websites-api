"""raptor/audit/site.py: "Website health": what can be measured from a company's own pages, certificate and response headers.

Everything here is read from the site itself. Nothing is guessed: a check the site would not let us make is `unknown`, never a problem.
`run(site)` returns (checks, context); the context (home page, extra pages) is reused by funnel.py so each page is fetched once.
"""
from __future__ import annotations

import random
import re
import socket
import ssl
import string
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib import robotparser
from urllib.parse import urlparse, urldefrag

from . import fetcher, htmlread
from .common import check, unknown

S = "website"
SKIP_LINK_HOSTS = ("linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "wa.me", "whatsapp.com", "t.me", "tiktok.com", "pinterest.com")
MAX_LINKS = 30
CONTACT_WORDS = re.compile(r"contact|get-in-touch|getintouch|enquir|inquir|quote|book|demo|reach-us|talk-to", re.I)
FREE_MAIL = ("gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "live.com", "rediffmail.com", "icloud.com", "proton.me", "protonmail.com", "aol.com")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class Ctx:
    """What the site checks learned that other modules need."""
    def __init__(self):
        self.home = None            # fetcher.Fetched of the page we treat as the home page
        self.page = None            # htmlread.Page of it
        self.pages = {}             # url -> htmlread.Page (home + up to 3 contact-like pages)
        self.refused = False
        self.refused_reason = ""
        self.reachable = False
        self.robots = None          # robotparser.RobotFileParser or None
        self.robots_text = ""
        self.emails = []            # plain-text addresses found on the pages read
        self.cert_ok = None


def _days_left(not_after_epoch: float) -> int:
    return int((not_after_epoch - time.time()) // 86400)


def _certificate(host: str):
    """(ok, days_left, issuer, error). Connects on 443 with full verification, exactly as a browser would."""
    try:
        fetcher.assert_public("https://%s/" % host)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
        return True, _days_left(expires), issuer, ""
    except ssl.SSLCertVerificationError as e:
        return False, None, "", (e.verify_message or str(e))[:160]
    except (ssl.SSLError, ConnectionResetError) as e:
        return False, None, "", "TLS error: %s" % str(e)[:120]
    except (socket.timeout, TimeoutError, OSError):
        return None, None, "", "could not connect on port 443"
    except fetcher.Unsafe:
        return None, None, "", "address not allowed"


def _robots(host: str, ctx: Ctx):
    res = fetcher.fetch("https://%s/robots.txt" % host, max_bytes=200_000, timeout=8)
    if res.ok and "<html" not in res.body[:500].lower():
        ctx.robots_text = res.body
        rp = robotparser.RobotFileParser()
        rp.parse(res.body.splitlines())
        ctx.robots = rp
        return res
    return res


def _allowed(ctx: Ctx, url: str) -> bool:
    if ctx.robots is None:
        return True
    try:
        return ctx.robots.can_fetch("*", url) and ctx.robots.can_fetch("RaptorAudit", url)
    except Exception:
        return True


def _bot_screen(res) -> bool:
    """The answer is a bot-protection screen (refused, or an almost empty page with no title, text or links), which proves nothing either way."""
    if res.error:
        return False
    if res.refused:
        return True
    if res.status == 200:
        p = htmlread.read(res.body, res.final_url)
        return not p.title.strip() and not p.links and p.text_len < 50 and not p.forms
    return False


def _first_answer(host: str):
    """The first of the usual front doors that gives an HTTP answer: https, https with www, plain http."""
    bare = host[4:] if host.startswith("www.") else host
    tried = []
    for url in ("https://%s/" % host, "https://www.%s/" % bare if host == bare else "https://%s/" % bare, "http://%s/" % host):
        res = fetcher.fetch(url)
        tried.append(res)
        if not res.error:
            return res, tried
    return None, tried


def _link_check(url: str):
    """('ok'|'broken'|'unverified', detail). HEAD first; a server that dislikes HEAD gets one GET."""
    res = fetcher.fetch(url, method="HEAD", timeout=8)
    if not res.error and res.status in (400, 403, 405, 501):
        res = fetcher.fetch(url, method="GET", timeout=8, max_bytes=20_000)
    if res.error in ("dns",):
        return "broken", "the address does not exist"
    if res.error:
        return "unverified", res.error_detail or res.error
    if res.status in (404, 410) or (500 <= res.status < 600 and res.status != 503):
        return "broken", "HTTP %d" % res.status
    if res.status in (401, 403, 429, 503, 999):
        return "unverified", "the site refuses automated checks (HTTP %d)" % res.status
    return "ok", ""


def _wp_current():
    res = fetcher.fetch("https://api.wordpress.org/core/version-check/1.7/", max_bytes=100_000, timeout=8)
    try:
        import json
        return json.loads(res.body)["offers"][0]["current"]
    except Exception:
        return None


def _ver(text: str):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def _security_headers(home):
    """The security-header check, from the headers the home page answered with (nothing is probed)."""
    h = home.headers
    wanted = [("strict-transport-security", "HSTS"), ("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"),
              ("referrer-policy", "Referrer-Policy")]
    present = [name for key, name in wanted if key in h]
    framing = ("x-frame-options" in h) or ("frame-ancestors" in h.get("content-security-policy", ""))
    if framing:
        present.append("Clickjacking protection")
    missing = [name for key, name in wanted if key not in h] + ([] if framing else ["Clickjacking protection"])
    status = "pass" if len(present) >= 4 else "warn" if len(present) >= 2 else "issue"
    return check("security_headers", S, "Security headers", status, value="%d of 5 present" % len(present), weight=2 if status == "issue" else 1, priority=28,
                     detail=("Present: " + (", ".join(present) or "none") + ". Missing: " + (", ".join(missing) or "none") + ". This only reads what the server sends; nothing was probed.") if missing else "All five common security headers are set.",
                     source="Response headers of the home page", verify="Open the browser's developer tools, Network tab, click the first request, and read Response Headers.",
                     fix="" if status == "pass" else "Ask the web host or developer to add the missing headers.")


def run(site: dict, light: bool = False):
    host = site["host"]
    ctx = Ctx()
    out = []
    home, tried = _first_answer(host)

    # ---- is there a website at all, and over https ----
    if home is None:
        errors = {t.error for t in tried}
        if errors == {"dns"}:
            out.append(check("site_reachable", S, "Website reachable", "issue", value="no website found", weight=3, priority=1,
                             detail="The address %s does not lead to a website: its name does not resolve." % host, source="DNS lookup of %s" % host,
                             verify="Open https://%s in a browser, or run: nslookup %s" % (host, host),
                             fix="Check that the domain points at the web host (DNS A/CNAME record)."))
        else:
            out.append(unknown("site_reachable", S, "Website reachable", "We could not get an answer from %s right now (%s). Try again later." % (host, ", ".join(sorted(errors)))))
        return out, ctx

    ctx.reachable = True
    ctx.home = home
    final = urlparse(home.final_url)
    served_https = final.scheme == "https"

    ok_cert, days, issuer, cert_err = _certificate(final.hostname or host)
    ctx.cert_ok = ok_cert
    if ok_cert is True:
        out.append(check("https_works", S, "Secure connection (HTTPS)", "pass", value="valid certificate", weight=3, priority=2,
                         detail="The certificate is valid%s." % ((", issued by " + issuer) if issuer else ""), source="TLS handshake with %s:443" % host,
                         verify="Open https://%s and click the padlock." % host))
        if days is not None:
            status = "issue" if days <= 21 else "warn" if days <= 45 else "pass"
            out.append(check("cert_expiry", S, "Certificate expiry", status, value="%d days left" % days, weight=2 if status != "pass" else 1, priority=3,
                             detail=("The certificate expires in %d days. When it does, browsers show a full-page security warning." % days) if status != "pass" else "The certificate has %d days left." % days,
                             source="TLS handshake with %s:443" % host, verify="Click the padlock in the browser, then Certificate, then 'Valid to'.",
                             fix="Renew the certificate now and turn on automatic renewal." if status != "pass" else ""))
    elif ok_cert is False:
        out.append(check("https_works", S, "Secure connection (HTTPS)", "issue", value="certificate problem", weight=3, priority=2,
                         detail="Browsers will warn visitors this site is not safe: %s." % cert_err, source="TLS handshake with %s:443" % host,
                         verify="Open https://%s in a browser." % host, fix="Install a valid certificate for this domain (free ones are available) and renew it automatically."))
    else:
        out.append(unknown("https_works", S, "Secure connection (HTTPS)", "We could not connect to port 443 to test the certificate (%s)." % cert_err))

    if ok_cert:
        plain = fetcher.fetch("http://%s/" % final.hostname)
        if plain.error:
            out.append(unknown("http_redirect", S, "Plain http goes to https", "We could not load the http:// version to test it (%s)." % (plain.error_detail or plain.error)))
        elif _bot_screen(plain):
            out.append(unknown("http_redirect", S, "Plain http goes to https", "The http:// address answered our automated visit with a bot-check screen, so we could not see where it leads."))
        elif urlparse(plain.final_url).scheme == "https":
            out.append(check("http_redirect", S, "Plain http goes to https", "pass", value="redirects to https", priority=4, source="GET http://%s/" % final.hostname,
                             verify="Type http://%s in the address bar and see that it changes to https." % final.hostname))
        else:
            out.append(check("http_redirect", S, "Plain http goes to https", "issue", value="stays on http", weight=2, priority=4,
                             detail="Visitors who type the address without https stay on an unencrypted page.", source="GET http://%s/" % final.hostname,
                             verify="Type http://%s in the address bar and see whether it changes to https." % final.hostname,
                             fix="Add a permanent (301) redirect from http to https."))

    # ---- www / non-www ----
    bare = final.hostname[4:] if (final.hostname or "").startswith("www.") else final.hostname
    other = ("www." + bare) if bare == final.hostname else bare
    alt = fetcher.fetch("https://%s/" % other, timeout=10)
    if alt.error in ("dns", "tls"):
        out.append(check("www_variant", S, "www and non-www both work", "issue", value="%s does not load" % other, weight=1, priority=25,
                         detail="Customers who type %s get an error, not your site." % other, source="GET https://%s/" % other,
                         verify="Open https://%s in a browser." % other, fix="Point both the www and the bare domain at the website and redirect one to the other."))
    elif alt.error:
        out.append(unknown("www_variant", S, "www and non-www both work", "We could not test %s (%s)." % (other, alt.error_detail or alt.error)))
    else:
        same = urlparse(alt.final_url).hostname == final.hostname
        out.append(check("www_variant", S, "www and non-www both work", "pass" if same else "warn", value="both reach the site" if same else "two separate addresses", priority=25,
                         detail="" if same else "Both %s and %s load, but they do not redirect to one address, so search engines may treat them as two sites." % (final.hostname, other),
                         source="GET https://%s/" % other, verify="Open both addresses and see whether they end at the same one.",
                         fix="" if same else "Redirect one address to the other with a permanent (301) redirect."))

    # ---- the page itself ----
    page = htmlread.read(home.body, home.final_url) if home.status < 400 else None
    # A bot-protection screen is a tiny page with no title, no text and no links: never judge a company by it.
    thin = page is not None and not page.title.strip() and not page.links and page.text_len < 50 and not page.forms
    if home.refused or thin:
        ctx.refused = True
        if home.refused and home.status in fetcher.REFUSED_STATUS:
            ctx.refused_reason = "The site refused our automated visit (HTTP %s)" % home.status
        elif home.refused:
            ctx.refused_reason = "The site showed our automated visit a bot-check screen instead of its page"
        else:
            ctx.refused_reason = "The site answered with an almost empty page, which is what a bot-protection screen looks like"
        why = ctx.refused_reason + ", so the checks that need its page content were skipped. We did not try to get around that."
        for cid, title in (("title", "Page title"), ("meta_description", "Search description"), ("viewport", "Mobile viewport"), ("sitemap", "Sitemap"), ("broken_links", "Broken links"), ("security_headers", "Security headers")):
            out.append(unknown(cid, S, title, why))
        return out, ctx

    if home.status >= 400:
        out.append(check("home_status", S, "Home page loads", "issue", value="HTTP %d" % home.status, weight=3, priority=1,
                         detail="The home page answered with an error.", source="GET %s" % home.final_url, verify="Open %s in a browser." % home.final_url,
                         fix="Fix the server error on the home page."))
        return out, ctx

    ctx.page = page
    ctx.pages[home.final_url] = page
    _robots(final.hostname, ctx)

    # a few contact-like pages (forms and phone numbers usually live there)
    seen = {urldefrag(home.final_url)[0]}
    extra = []
    for link in page.links:
        href = urldefrag(link["href"])[0]
        p = urlparse(href)
        if p.scheme in ("http", "https") and (p.hostname or "").removeprefix("www.") == bare.removeprefix("www.") and href not in seen and CONTACT_WORDS.search(href + " " + link["text"]) and _allowed(ctx, href):
            seen.add(href)
            extra.append(href)
        if len(extra) >= 3:
            break
    with ThreadPoolExecutor(max_workers=3) as pool:
        for url, res in zip(extra, pool.map(lambda u: fetcher.fetch(u, timeout=10), extra)):
            if res.ok and not res.refused:
                ctx.pages[res.final_url] = htmlread.read(res.body, res.final_url)

    heavy = page.js_heavy

    # title
    title = page.title
    if title:
        long_ = len(title) > 65
        out.append(check("title", S, "Page title", "warn" if long_ else "pass", value=title[:90], priority=40, source="<title> of the home page",
                         detail="The title is %d characters; Google usually shows about 60." % len(title) if long_ else "", verify="Right-click the page, View Source, and search for <title>.",
                         fix="Shorten the title to about 60 characters." if long_ else ""))
    elif heavy:
        out.append(unknown("title", S, "Page title", "This site builds its pages with scripts, so a plain read could not find the title."))
    else:
        out.append(check("title", S, "Page title", "issue", value="missing", weight=2, priority=40, detail="The home page has no title, so search results and browser tabs show a bare address.",
                         source="<title> of the home page", verify="Right-click the page, View Source, and search for <title>.", fix="Give every page a clear title with the company name and what it does."))

    desc = page.meta_value("description")
    if desc:
        out.append(check("meta_description", S, "Search description", "pass", value=desc[:120], priority=41, source='<meta name="description"> of the home page', verify="View Source and search for name=\"description\"."))
    elif heavy:
        out.append(unknown("meta_description", S, "Search description", "This site builds its pages with scripts, so a plain read could not find the description."))
    else:
        out.append(check("meta_description", S, "Search description", "issue", value="missing", priority=41, detail="Without a description Google picks random text from the page for your search result.",
                         source='<meta name="description"> of the home page', verify="View Source and search for name=\"description\".", fix="Write a 140 to 160 character description of what you offer and where."))

    if page.h1 == 1 or heavy and not page.h1:
        if page.h1 == 1:
            out.append(check("h1", S, "One main heading (H1)", "pass", value="1", priority=45, source="<h1> tags on the home page"))
        else:
            out.append(unknown("h1", S, "One main heading (H1)", "This site builds its pages with scripts, so a plain read could not find the headings."))
    elif page.h1 == 0:
        out.append(check("h1", S, "One main heading (H1)", "warn", value="none", priority=45, detail="The home page has no main heading for search engines and screen readers.", source="<h1> tags on the home page", fix="Add one H1 that says what the company does."))
    else:
        out.append(check("h1", S, "One main heading (H1)", "warn", value="%d found" % page.h1, priority=45, detail="Several H1 headings dilute what the page is about.", source="<h1> tags on the home page", fix="Keep one H1 per page."))

    viewport = page.meta_value("viewport")
    out.append(check("viewport", S, "Mobile viewport", "pass" if viewport else ("unknown" if heavy else "issue"), value=viewport or None, weight=2, priority=30,
                     detail="" if viewport else ("This site builds its pages with scripts, so a plain read could not find the tag." if heavy else "Without a viewport tag phones show a shrunken desktop page."),
                     source='<meta name="viewport"> of the home page', verify='View Source and search for name="viewport".', fix="" if viewport else 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.'))

    og = [k for k in ("og:title", "og:description", "og:image") if page.meta_value(k)]
    if len(og) == 3:
        out.append(check("open_graph", S, "Link preview (Open Graph)", "pass", value="title, description, image", priority=50, source="og: tags of the home page"))
    elif heavy:
        out.append(unknown("open_graph", S, "Link preview (Open Graph)", "This site builds its pages with scripts, so a plain read could not find the tags."))
    else:
        out.append(check("open_graph", S, "Link preview (Open Graph)", "warn", value="missing: " + ", ".join(k for k in ("og:title", "og:description", "og:image") if k not in og), priority=50,
                         detail="When the link is shared on WhatsApp or LinkedIn it shows without a proper image or text.", source="og: tags of the home page",
                         verify="Paste the address in a WhatsApp chat and look at the preview.", fix="Add og:title, og:description and og:image tags."))

    icon = "yes" if (page.has_rel("icon") or page.has_rel("shortcut")) else None
    if icon is None and not heavy:
        fav = fetcher.fetch("https://%s/favicon.ico" % final.hostname, method="HEAD", timeout=8)
        icon = "yes" if (not fav.error and fav.status == 200) else "no" if (not fav.error and fav.status in (404, 410)) else "unknown"
    if icon == "yes":
        out.append(check("favicon", S, "Site icon (favicon)", "pass", value="present", priority=52, source="<link rel=icon> or /favicon.ico"))
    elif heavy or icon == "unknown":
        out.append(unknown("favicon", S, "Site icon (favicon)", "This site builds its pages with scripts, so a plain read could not find the icon." if heavy else "We could not test /favicon.ico (the site did not give a clear answer)."))
    else:
        out.append(check("favicon", S, "Site icon (favicon)", "warn", value="missing", priority=52, detail="Browser tabs and bookmarks show a blank icon.", source="<link rel=icon> and /favicon.ico", fix="Add a favicon."))

    structured = page.ldjson > 0 or page.microdata
    if structured:
        out.append(check("structured_data", S, "Structured data", "pass", value="found", priority=48, source="JSON-LD and microdata on the home page"))
    elif heavy:
        out.append(unknown("structured_data", S, "Structured data", "This site builds its pages with scripts, so a plain read could not find structured data."))
    else:
        out.append(check("structured_data", S, "Structured data", "warn", value="none", priority=48,
                         detail="No machine-readable business details (name, address, phone, hours) for Google to show in results.", source="JSON-LD and microdata on the home page",
                         verify="Paste the address into Google's Rich Results Test.", fix="Add Organization / LocalBusiness structured data."))

    if light:           # the competitor comparison needs only the basics, not a crawl
        out.append(_security_headers(home))
        return out, ctx

    # sitemap
    sitemap_url = None
    for line in ctx.robots_text.splitlines():
        if line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            break
    sm = fetcher.fetch(sitemap_url or "https://%s/sitemap.xml" % final.hostname, max_bytes=300_000, timeout=8)
    if (not sm.error) and sm.status == 200 and ("<urlset" in sm.body[:3000] or "<sitemapindex" in sm.body[:3000]):
        out.append(check("sitemap", S, "Sitemap", "pass", value=sm.final_url, priority=46, source="robots.txt and /sitemap.xml"))
    elif sm.error:
        out.append(unknown("sitemap", S, "Sitemap", "We could not load the sitemap address to test it (%s)." % (sm.error_detail or sm.error)))
    elif sm.status not in (200, 404, 410):
        out.append(unknown("sitemap", S, "Sitemap", "The sitemap address answered HTTP %d (a refusal or a server problem is not the same as 'missing'), so we could not tell." % sm.status))
    else:
        out.append(check("sitemap", S, "Sitemap", "warn", value="not found", priority=46, detail="Neither robots.txt nor /sitemap.xml points to a sitemap, so search engines find pages more slowly.",
                         source="robots.txt and /sitemap.xml", verify="Open https://%s/sitemap.xml." % final.hostname, fix="Publish /sitemap.xml and list it in robots.txt."))

    # custom 404
    probe = "https://%s/raptor-audit-%s" % (final.hostname, "".join(random.choices(string.ascii_lowercase, k=10)))
    nf = fetcher.fetch(probe, timeout=8, max_bytes=100_000)
    if nf.error:
        out.append(unknown("not_found_page", S, "Missing pages return 404", "We could not test a missing page (%s)." % (nf.error_detail or nf.error)))
    elif nf.status == 404:
        out.append(check("not_found_page", S, "Missing pages return 404", "pass", value="HTTP 404", priority=55, source="GET of an address that cannot exist"))
    elif nf.status == 200 and _bot_screen(nf):
        out.append(unknown("not_found_page", S, "Missing pages return 404", "The test address returned a bot-check screen, so we could not see how missing pages behave."))
    elif nf.status == 200:
        out.append(check("not_found_page", S, "Missing pages return 404", "warn", value="HTTP 200", priority=55, detail="An address that does not exist answers 'OK' instead of 'not found', which confuses search engines.",
                         source="GET " + probe, verify="Open " + probe + " and see what the browser's network tab reports.", fix="Make missing pages return a real 404 status."))
    else:
        out.append(unknown("not_found_page", S, "Missing pages return 404", "The test address answered HTTP %d, which does not tell us how normal missing pages behave." % nf.status))

    # broken links
    links, seen_links = [], set()
    for pg in ctx.pages.values():
        for link in pg.links:
            href = urldefrag(link["href"])[0]
            p = urlparse(href)
            if p.scheme not in ("http", "https") or href in seen_links:
                continue
            seen_links.add(href)
            links.append(href)
    skipped_social = [u for u in links if any((urlparse(u).hostname or "").endswith(h) for h in SKIP_LINK_HOSTS)]
    candidates = [u for u in links if u not in skipped_social]
    internal = [u for u in candidates if (urlparse(u).hostname or "").removeprefix("www.") == bare.removeprefix("www.")]
    external = [u for u in candidates if u not in internal]
    chosen = [u for u in internal if _allowed(ctx, u)][:MAX_LINKS] + external[:max(0, MAX_LINKS - len(internal))][:10]
    if chosen:
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(_link_check, chosen))
        broken = [(u, d) for u, (s, d) in zip(chosen, results) if s == "broken"]
        unverified = sum(1 for s, _ in results if s == "unverified")
        scope = "Checked %d links on %d page(s)%s." % (len(chosen), len(ctx.pages), ("; %d could not be verified" % unverified) if unverified else "")
        if skipped_social:
            scope += " %d social-media links were not tested (those sites block automated checks)." % len(skipped_social)
        if broken:
            out.append(check("broken_links", S, "Broken links", "issue", value="%d broken of %d checked" % (len(broken), len(chosen)), weight=2, priority=42,
                             detail=scope + " Broken: " + "; ".join("%s (%s)" % (u, d) for u, d in broken[:8]), source="Each link on the home page and %d contact-type page(s)" % max(0, len(ctx.pages) - 1),
                             verify="Click the links listed.", fix="Fix or remove the broken links.", evidence=[{"url": u, "reason": d} for u, d in broken[:20]]))
        else:
            out.append(check("broken_links", S, "Broken links", "pass", value="none in %d checked" % len(chosen), priority=42, detail=scope, source="Each link on the home page and its contact-type pages"))
    else:
        out.append(unknown("broken_links", S, "Broken links", "No links to test were found on the pages we could read."))

    out.append(_security_headers(home))

    # visible software versions
    gen = page.meta_value("generator")
    m = re.search(r"wordpress\s+([\d.]+)", gen, re.I)
    if m:
        latest = _wp_current()
        if latest:
            behind = _ver(m.group(1))[:2] < _ver(latest)[:2]
            out.append(check("wordpress_version", S, "WordPress version", "issue" if behind else "pass", value="%s (current is %s)" % (m.group(1), latest), weight=2 if behind else 1, priority=22,
                             detail="The site tells every visitor it runs WordPress %s. The current release is %s; older versions stop receiving security fixes." % (m.group(1), latest) if behind
                             else "The site runs a current WordPress release.", source='<meta name="generator"> on the home page, compared with api.wordpress.org', verify='View Source, search for name="generator"; compare with wordpress.org/download.',
                             fix="Update WordPress, then its plugins and theme." if behind else ""))
        else:
            out.append(check("wordpress_version", S, "WordPress version", "info", value=m.group(1), detail="The site shows its WordPress version; we could not look up the current release to compare.", source='<meta name="generator">'))
    jq = re.search(r"jquery[-.]((\d+)\.\d+(?:\.\d+)?)(?:\.min)?\.js", page.script_blob, re.I)
    if jq and int(jq.group(2)) <= 2:
        out.append(check("jquery_version", S, "Old jQuery library", "warn", value="jQuery " + jq.group(1), priority=23,
                         detail="jQuery 1.x and 2.x no longer receive updates from the jQuery team.", source="Script address loaded by the home page", verify="View Source and search for 'jquery'.", fix="Update to a current jQuery release, or remove it."))

    # privacy / terms
    legal = [l for l in page.links if re.search(r"privacy|cookie|terms|disclaimer", (l["href"] + " " + l["text"]), re.I)]
    privacy = [l for l in legal if re.search(r"privacy", (l["href"] + " " + l["text"]), re.I)]
    if privacy:
        out.append(check("privacy_page", S, "Privacy policy link", "pass", value=privacy[0]["href"], priority=47, source="Links on the home page"))
    elif heavy:
        out.append(unknown("privacy_page", S, "Privacy policy link", "This site builds its pages with scripts, so a plain read could not see its footer links."))
    else:
        has_forms = any(f["inputs"] or f["textarea"] for pg in ctx.pages.values() for f in pg.forms)
        out.append(check("privacy_page", S, "Privacy policy link", "issue" if has_forms else "warn", value="not found", weight=1, priority=47,
                         detail="No link containing 'privacy' was found on the pages we read" + (", and the site collects visitors' details in forms." if has_forms else "."), source="Links on the home page and contact-type pages",
                         verify="Scroll to the footer and look for a Privacy link.", fix="Publish a privacy policy and link it from the footer and next to every form."))

    # contact details shown in plain text
    found = set()
    for pg in ctx.pages.values():
        for m_ in EMAIL_RE.findall(pg.raw):
            if not m_.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")):
                found.add(m_.lower())
        for l in pg.links:
            if l["href"].lower().startswith("mailto:"):
                found.add(l["href"][7:].split("?")[0].strip().lower())
    ctx.emails = sorted(found)
    free = [e for e in ctx.emails if e.split("@")[-1] in FREE_MAIL]
    if free:
        out.append(check("free_mail_contact", S, "Public contact uses a free email", "warn", value=free[0], priority=44,
                         detail="The site publishes %s. A free mailbox on a business site looks less trustworthy to customers." % free[0], source="Text and mailto links on the pages we read",
                         verify="Look at the contact details on the site.", fix="Use an address on the company's own domain."))
    if ctx.emails:
        out.append(check("emails_exposed", S, "Email addresses in plain text", "info", value=", ".join(ctx.emails[:5]), priority=70,
                         detail="These addresses can be read by anyone and by spam robots that harvest them.", source="Text and mailto links on the pages we read"))

    careers = [l for l in page.links if re.search(r"career|jobs|hiring|join-us|work-with-us", l["href"] + " " + l["text"], re.I)]
    if careers:
        out.append(check("careers_page", S, "Careers page", "info", value=careers[0]["href"], priority=90, detail="The site links to a careers page, which usually means the company is hiring or growing.", source="Links on the home page"))

    h = home.headers
    server = h.get("server", "")
    cdn = next((n for key, n in (("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-served-by", "Fastly"), ("x-vercel-id", "Vercel"), ("x-nf-request-id", "Netlify"), ("x-akamai", "Akamai")) if key in h), None)
    if cdn or server:
        out.append(check("hosting_signal", S, "Hosting signals", "info", value=cdn or server, priority=91, detail="Read from response headers only; it says what answered, not where the company's servers physically are.", source="Response headers of the home page"))

    out.append(check("page_size", S, "Home page HTML size", "info", value="%d KB" % round(home.size / 1000), priority=92, source="Size of the home page HTML only (images and scripts are measured by the speed test)"))
    return out, ctx

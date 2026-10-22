"""tests/test_audit.py: the Company Audit (raptor/audit). No network: pages, DNS, the registry and Google's speed test are all faked.

The rule these tests protect: a finding is only shown if it was MEASURED. A refusal, a bot-check page, a rate limit or a DNS hiccup is
`unknown`, never a problem."""
import ipaddress
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from raptor.audit import common, domain, engine, fetcher, funnel, htmlread, site, speed  # noqa: F401
from raptor.audit.common import check, normalize_site, ordered_problems, score
from raptor.audit.fetcher import Fetched
from raptor.audit.router import router
from raptor.utility.raptor_auth import get_current_user


def by_id(checks):
    return {c["id"]: c for c in checks}


# ---------------------------------------------------------------- common

def test_site_addresses_are_normalised_and_odd_ones_refused():
    assert normalize_site("https://www.Acme.com/about?x=1")["host"] == "www.acme.com"
    assert normalize_site("acme.co.in")["registrable"] == "acme.co.in"
    assert normalize_site("shop.acme.co.in")["registrable"] == "acme.co.in"
    assert normalize_site("blog.acme.com")["registrable"] == "acme.com"
    for bad in ("", "localhost", "10.0.0.1", "http://169.254.169.254/", "acme", "a b.com", "acme.com:8080", "x" * 400 + ".com"):
        assert normalize_site(bad) is None, bad


def test_score_ignores_unknown_and_info_and_says_how_many_checks_it_uses():
    checks = [check("a", "s", "A", "pass", weight=2), check("b", "s", "B", "issue", weight=2), check("c", "s", "C", "warn", weight=2),
              check("d", "s", "D", "unknown"), check("e", "s", "E", "info")]
    s = score(checks)
    assert s["value"] == 50 and s["based_on"] == 3 and s["of"] == 4 and s["unknown"] == 1
    assert score([check("d", "s", "D", "unknown")])["value"] is None


def test_problems_come_in_the_fixed_published_order():
    checks = [check("late", "s", "Late", "issue", priority=60), check("early", "s", "Early", "issue", priority=5), check("w", "s", "W", "warn", priority=1)]
    assert [c["id"] for c in ordered_problems(checks)] == ["early", "late", "w"]


# ---------------------------------------------------------------- fetcher / SSRF guard

@pytest.mark.parametrize("raw,public", [("93.184.216.34", True), ("2606:4700:10::6814:179a", True), ("10.0.0.5", False), ("127.0.0.1", False), ("169.254.169.254", False),
                                        ("192.168.1.1", False), ("100.64.0.1", False), ("::1", False), ("fe80::1", False), ("0.0.0.0", False),
                                        ("64:ff9b::a00:1", False),                 # NAT64 wrapper around 10.0.0.1
                                        ("64:ff9b::b9c7:6e99", True),              # NAT64 wrapper around a public address: real sites on IPv6-only networks
                                        ("::ffff:10.0.0.1", False), ("::ffff:93.184.216.34", True)])
def test_only_addresses_on_the_open_internet_are_allowed(raw, public):
    assert fetcher.is_public_ip(raw) is public


def test_a_host_that_resolves_to_a_private_address_is_never_contacted(monkeypatch):
    monkeypatch.setattr(fetcher, "_resolve", lambda host: ["93.184.216.34", "10.0.0.7"])
    res = fetcher.fetch("http://sneaky.example/")
    assert res.error == "blocked" and res.status == 0


def test_a_dns_hiccup_is_not_reported_as_a_missing_domain(monkeypatch):
    monkeypatch.setattr(fetcher, "_resolve", lambda host: None)
    assert fetcher.fetch("https://acme.example/").error == "other"
    monkeypatch.setattr(fetcher, "_resolve", lambda host: [])
    assert fetcher.fetch("https://acme.example/").error == "dns"


def test_only_standard_ports_and_no_credentials():
    for url in ("http://acme.example:8080/", "https://user:pw@acme.example/", "ftp://acme.example/"):
        with pytest.raises(fetcher.Unsafe):
            fetcher.assert_public(url)


# ---------------------------------------------------------------- html reader

PAGE = """<!doctype html><html lang="en"><head><title> Acme  Robots </title><meta name="description" content="We build robots">
<meta name="viewport" content="width=device-width"><link rel="icon" href="/f.ico"><script src="/a.js"></script>
<script>gtag('config','G-1')</script><script type="application/ld+json">{}</script></head>
<body><h1>Acme</h1><a href="/contact">Contact us</a><a href="tel:+911234">Call</a><a href="mailto:hi@acme.com">Mail</a>
<form action="/send" method="post"><input name="email" type="email"><textarea name="message"></textarea><button type="submit">Send</button></form>
<img src="/x.png"><p>Some real text about the company goes here.</p></body></html>"""


def test_the_reader_finds_the_facts_on_a_page():
    p = htmlread.read(PAGE, "https://acme.com/")
    assert p.title == "Acme Robots" and p.lang == "en" and p.meta_value("description") == "We build robots" and p.h1 == 1
    assert p.has_rel("icon") and p.ldjson == 1 and "https://acme.com/a.js" in p.scripts and any("gtag" in s for s in p.inline_scripts)
    assert [l["href"] for l in p.links] == ["https://acme.com/contact", "tel:+911234", "mailto:hi@acme.com"]
    assert p.forms[0]["textarea"] and p.forms[0]["submit"] and p.imgs == ["https://acme.com/x.png"]
    assert not p.js_heavy


def test_a_page_built_by_scripts_is_recognised():
    html = '<html><body><div id="root"></div><script src="/1.js"></script><script src="/2.js"></script><script src="/3.js"></script></body></html>'
    assert htmlread.read(html, "https://app.example/").js_heavy


# ---------------------------------------------------------------- site checks

class FakeWeb:
    """Stands in for fetcher.fetch: a dict of url -> Fetched (or a callable), anything else is a 404."""
    def __init__(self, pages):
        self.pages, self.asked = pages, []

    def __call__(self, url, **kw):
        self.asked.append((kw.get("method", "GET"), url))
        got = self.pages.get(url)
        if callable(got):
            got = got(url)
        return got if got is not None else Fetched(url=url, final_url=url, status=404, body="not found", size=9)


def page(url, html=PAGE, status=200, headers=None):
    return Fetched(url=url, final_url=url, status=status, body=html, size=len(html), headers=headers or {}, redirects=[url])


@pytest.fixture
def web(monkeypatch):
    pages = {"https://acme.com/": page("https://acme.com/"),
             "http://acme.com/": Fetched(url="http://acme.com/", final_url="https://acme.com/", status=200, body=PAGE, redirects=["http://acme.com/", "https://acme.com/"]),
             "https://www.acme.com/": Fetched(url="https://www.acme.com/", final_url="https://acme.com/", status=200, body=PAGE, redirects=["https://www.acme.com/", "https://acme.com/"]),
             "https://acme.com/robots.txt": page("https://acme.com/robots.txt", "User-agent: *\nSitemap: https://acme.com/sitemap.xml"),
             "https://acme.com/sitemap.xml": page("https://acme.com/sitemap.xml", "<urlset></urlset>"),
             "https://acme.com/contact": page("https://acme.com/contact", "<html><title>Contact</title><body><form><input type=email name=email><textarea></textarea></form></body></html>")}
    fake = FakeWeb(pages)
    monkeypatch.setattr(site.fetcher, "fetch", fake)
    monkeypatch.setattr(site, "_certificate", lambda host: (True, 200, "Let's Encrypt", ""))
    monkeypatch.setattr(site, "_wp_current", lambda: "6.8.1")
    return fake


def run_site(host="acme.com"):
    checks, ctx = site.run(normalize_site(host))
    return by_id(checks), ctx


def test_a_healthy_page_passes_the_basics(web):
    c, ctx = run_site()
    for cid in ("https_works", "cert_expiry", "http_redirect", "www_variant", "title", "meta_description", "viewport", "h1", "sitemap", "favicon", "structured_data"):
        assert c[cid]["status"] == "pass", (cid, c[cid])
    assert c["not_found_page"]["status"] == "pass"
    assert ctx.reachable and ctx.page.title == "Acme Robots"


def test_a_certificate_close_to_expiry_is_an_issue_with_the_date_in_days(web, monkeypatch):
    monkeypatch.setattr(site, "_certificate", lambda host: (True, 9, "x", ""))
    assert run_site()[0]["cert_expiry"]["status"] == "issue"
    monkeypatch.setattr(site, "_certificate", lambda host: (False, None, "", "certificate has expired"))
    c = run_site()[0]
    assert c["https_works"]["status"] == "issue" and "expired" in c["https_works"]["detail"]


def test_missing_description_and_plain_http_staying_on_http_are_real_issues(web):
    web.pages["https://acme.com/"] = page("https://acme.com/", "<html><head><title>Acme</title></head><body><h1>Hi</h1><a href='/x'>x</a><p>" + "text " * 100 + "</p></body></html>")
    web.pages["http://acme.com/"] = Fetched(url="http://acme.com/", final_url="http://acme.com/", status=200, body="<html><title>Acme</title><a href='/'>x</a>" + "word " * 40 + "</html>")
    c, _ = run_site()
    assert c["meta_description"]["status"] == "issue" and c["http_redirect"]["status"] == "issue"


def test_a_bot_check_screen_proves_nothing_in_either_direction(web):
    screen = '<html><head><meta http-equiv="refresh" content="5; URL=\'/?bm-verify=abc\'"><title>&nbsp;</title></head><body><iframe></iframe></body></html>'
    web.pages["https://acme.com/"] = page("https://acme.com/", screen)
    web.pages["http://acme.com/"] = page("http://acme.com/", screen)             # the same screen on plain http: must NOT be read as "stays on http"
    c, ctx = run_site()
    assert ctx.refused and ctx.page is None
    for cid in ("title", "meta_description", "viewport", "sitemap", "broken_links", "security_headers"):
        assert c[cid]["status"] == "unknown", cid
    assert c["http_redirect"]["status"] == "unknown"
    assert not [x for x in c.values() if x["status"] == "issue"]


def test_a_403_is_a_refusal_and_we_stop_there(web):
    web.pages["https://acme.com/"] = page("https://acme.com/", "Forbidden", status=403)
    c, ctx = run_site()
    assert ctx.refused and "HTTP 403" in c["title"]["detail"] and "did not try to get around" in c["title"]["detail"]


def test_a_rate_limited_sitemap_or_favicon_is_unknown_never_missing(web):
    web.pages["https://acme.com/robots.txt"] = page("https://acme.com/robots.txt", "User-agent: *")
    web.pages["https://acme.com/sitemap.xml"] = page("https://acme.com/sitemap.xml", "slow down", status=429)
    html = PAGE.replace('<link rel="icon" href="/f.ico">', "")
    web.pages["https://acme.com/"] = page("https://acme.com/", html)
    web.pages["https://acme.com/favicon.ico"] = page("https://acme.com/favicon.ico", "", status=429)
    c, _ = run_site()
    assert c["sitemap"]["status"] == "unknown" and c["favicon"]["status"] == "unknown"
    web.pages["https://acme.com/sitemap.xml"] = page("https://acme.com/sitemap.xml", "nope", status=404)
    web.pages["https://acme.com/favicon.ico"] = page("https://acme.com/favicon.ico", "", status=404)
    c, _ = run_site()
    assert c["sitemap"]["status"] == "warn" and c["favicon"]["status"] == "warn"


def test_broken_links_are_counted_with_their_scope_and_social_sites_are_not_tested(web):
    html = ("<html><head><title>Acme</title></head><body><h1>A</h1><p>" + "text " * 100 + "</p><a href='/ok'>ok</a><a href='/gone'>gone</a>"
            "<a href='https://www.linkedin.com/company/acme'>in</a><a href='https://partner.example/x'>p</a></body></html>")
    web.pages["https://acme.com/"] = page("https://acme.com/", html)
    web.pages["https://acme.com/ok"] = page("https://acme.com/ok", "fine")
    web.pages["https://partner.example/x"] = page("https://partner.example/x", "blocked", status=403)     # a refusal, not a broken link
    c, _ = run_site()
    b = c["broken_links"]
    assert b["status"] == "issue" and b["value"] == "1 broken of 3 checked" and "https://acme.com/gone" in b["detail"]
    assert "social-media links were not tested" in b["detail"] and "could not be verified" in b["detail"]
    assert not any("linkedin" in m for _, m in web.asked)


def test_a_missing_page_that_answers_ok_is_flagged_but_a_bot_screen_is_not(web, monkeypatch):
    monkeypatch.setattr(site.random, "choices", lambda population, k: ["a"] * k)            # the probe address becomes predictable
    probe = "https://acme.com/raptor-audit-aaaaaaaaaa"
    web.pages[probe] = page(probe, PAGE)                                                      # a normal page for an address that cannot exist
    assert run_site()[0]["not_found_page"]["status"] == "warn"
    web.pages[probe] = page(probe, '<html><head><meta http-equiv="refresh" content="5; URL=/?bm-verify=x"><title>&nbsp;</title></head><body></body></html>')
    assert run_site()[0]["not_found_page"]["status"] == "unknown"
    web.pages.pop(probe)
    assert run_site()[0]["not_found_page"]["status"] == "pass"


def test_security_headers_are_counted_from_the_response(web):
    web.pages["https://acme.com/"] = page("https://acme.com/", PAGE, headers={"strict-transport-security": "max-age=1", "x-content-type-options": "nosniff",
                                                                              "referrer-policy": "no-referrer", "content-security-policy": "frame-ancestors 'self'"})
    assert run_site()[0]["security_headers"]["status"] == "pass"
    web.pages["https://acme.com/"] = page("https://acme.com/", PAGE)
    assert run_site()[0]["security_headers"]["value"] == "0 of 5 present"


def test_an_old_wordpress_is_an_issue_only_when_the_site_shows_its_version(web):
    web.pages["https://acme.com/"] = page("https://acme.com/", PAGE.replace("<title>", '<meta name="generator" content="WordPress 5.8.1"><title>'))
    c, _ = run_site()
    assert c["wordpress_version"]["status"] == "issue" and "6.8.1" in c["wordpress_version"]["value"]
    web.pages["https://acme.com/"] = page("https://acme.com/", PAGE.replace("<title>", '<meta name="generator" content="WordPress 6.8.0"><title>'))
    assert run_site()[0]["wordpress_version"]["status"] == "pass"


def test_a_dead_domain_is_an_issue_but_a_timeout_is_only_unknown(monkeypatch):
    dead = lambda url, **kw: Fetched(url=url, final_url=url, error="dns", error_detail="x")
    monkeypatch.setattr(site.fetcher, "fetch", dead)
    assert by_id(site.run(normalize_site("gone.example"))[0])["site_reachable"]["status"] == "issue"
    slow = lambda url, **kw: Fetched(url=url, final_url=url, error="timeout", error_detail="x")
    monkeypatch.setattr(site.fetcher, "fetch", slow)
    assert by_id(site.run(normalize_site("slow.example"))[0])["site_reachable"]["status"] == "unknown"


def test_a_free_mailbox_published_on_the_site_is_noted(web):
    web.pages["https://acme.com/"] = page("https://acme.com/", PAGE.replace("<p>", "<p>Write to boss@gmail.com or "))
    c, ctx = run_site()
    assert c["free_mail_contact"]["status"] == "warn" and "boss@gmail.com" in ctx.emails


# ---------------------------------------------------------------- domain and email

class FakeDns:
    def __init__(self, txt=None, mx=None):
        self.t, self.m = txt or {}, mx

    def txt(self, name):
        v = self.t.get(name, [])
        return v

    def mx(self, name):
        return ["aspmx.l.google.com"] if self.m is None else self.m


@pytest.fixture
def dns_env(monkeypatch):
    def install(txt=None, mx=None, rdap=None):
        f = FakeDns(txt, mx)
        monkeypatch.setattr(domain, "_txt", f.txt)
        monkeypatch.setattr(domain, "_mx", f.mx)
        monkeypatch.setattr(domain, "_rdap", lambda d: rdap if rdap is not None else (None, "the registry did not answer (timeout)"))
    return install


def rdap_for(days_left, years=5):
    now = datetime.now(timezone.utc)
    return ({"events": [{"eventAction": "registration", "eventDate": (now - timedelta(days=int(365.25 * years))).isoformat()},
                        {"eventAction": "expiration", "eventDate": (now + timedelta(days=days_left, hours=1)).isoformat()}],
             "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Acme Registrar"]]]}]}, "")


def test_missing_dmarc_and_spf_on_a_domain_with_email_are_issues(dns_env):
    dns_env(txt={}, rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["dmarc"]["status"] == "issue" and "5,000" in c["dmarc"]["detail"] and c["spf"]["status"] == "issue"
    assert c["domain_expiry"]["status"] == "pass" and c["domain_age"]["status"] == "info" and c["registrar"]["value"] == "Acme Registrar"


def test_dmarc_policy_none_is_a_warning_and_reject_passes(dns_env):
    dns_env(txt={"_dmarc.acme.com": ["v=DMARC1; p=none; rua=mailto:a@acme.com"], "acme.com": ["v=spf1 include:_spf.google.com ~all"]}, rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["dmarc"]["status"] == "warn" and c["spf"]["status"] == "pass"
    dns_env(txt={"_dmarc.acme.com": ["v=DMARC1; p=reject"], "acme.com": ["v=spf1 -all"]}, rdap=rdap_for(200))
    assert by_id(domain.run(normalize_site("acme.com")))["dmarc"]["status"] == "pass"


def test_spf_that_allows_everyone_or_is_duplicated_is_an_issue(dns_env):
    dns_env(txt={"acme.com": ["v=spf1 +all"]}, rdap=rdap_for(200))
    assert by_id(domain.run(normalize_site("acme.com")))["spf"]["status"] == "issue"
    dns_env(txt={"acme.com": ["v=spf1 -all", "v=spf1 include:x.com ~all"]}, rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["spf"]["status"] == "issue" and "2 SPF records" in c["spf"]["value"]


def test_spf_over_ten_lookups_is_counted_through_the_includes(dns_env):
    txt = {"acme.com": ["v=spf1 mx " + " ".join("include:s%d.example" % i for i in range(8)) + " a:mail.acme.com include:big.example -all"],
           "big.example": ["v=spf1 include:a.example include:b.example -all"]}
    dns_env(txt=txt, rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["spf_lookups"]["status"] == "issue" and "13 lookups" in c["spf_lookups"]["value"]


def test_a_dns_timeout_is_unknown_not_a_missing_record(dns_env, monkeypatch):
    dns_env(rdap=rdap_for(200))
    monkeypatch.setattr(domain, "_txt", lambda name: None)
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["spf"]["status"] == "unknown" and c["dmarc"]["status"] == "unknown"


def test_dkim_not_found_is_information_and_found_is_a_pass(dns_env):
    dns_env(txt={}, rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["dkim"]["status"] == "info" and "does not prove DKIM is missing" in c["dkim"]["detail"]
    dns_env(txt={"google._domainkey.acme.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"]}, rdap=rdap_for(200))
    assert by_id(domain.run(normalize_site("acme.com")))["dkim"]["status"] == "pass"


def test_a_domain_close_to_expiry_is_an_issue_and_a_silent_registry_is_unknown(dns_env):
    dns_env(rdap=rdap_for(20))
    assert by_id(domain.run(normalize_site("acme.com")))["domain_expiry"]["status"] == "issue"
    dns_env(rdap=rdap_for(80))
    assert by_id(domain.run(normalize_site("acme.com")))["domain_expiry"]["status"] == "warn"
    dns_env()          # registry did not answer
    assert by_id(domain.run(normalize_site("acme.com")))["domain_expiry"]["status"] == "unknown"


def test_no_mail_servers_is_stated_as_a_fact(dns_env):
    dns_env(mx=[], rdap=rdap_for(200))
    c = by_id(domain.run(normalize_site("acme.com")))
    assert c["mx"]["status"] == "warn" and c["spf"]["weight"] == 1          # no mail at all: a missing SPF matters less
    assert "dkim" not in c


# ---------------------------------------------------------------- funnel

def ctx_for(html, base="https://acme.com/", extra=None):
    ctx = site.Ctx()
    ctx.page = htmlread.read(html, base)
    ctx.pages[base] = ctx.page
    for url, h in (extra or {}).items():
        ctx.pages[url] = htmlread.read(h, url)
    return ctx


def test_funnel_finds_what_is_there():
    c = by_id(funnel.run(ctx_for(PAGE)))
    assert c["contact_path"]["status"] == "pass" and c["contact_form"]["status"] == "pass" and c["click_to_call"]["status"] == "pass"
    assert c["analytics"]["status"] == "pass" and "Google Analytics" in c["analytics"]["value"]


def test_funnel_absence_is_an_issue_on_a_normal_page_and_carries_the_caveat():
    html = "<html><head><title>Acme</title></head><body><h1>Acme</h1><p>" + "plain words " * 80 + "</p><a href='/about'>About</a></body></html>"
    c = by_id(funnel.run(ctx_for(html)))
    assert c["contact_path"]["status"] == "issue" and "cannot be seen by a plain read" in c["contact_path"]["detail"]
    assert c["analytics"]["status"] == "issue" and c["whatsapp_button"]["status"] == "warn"


def test_a_script_built_page_makes_absence_unknown_not_a_problem():
    html = '<html><body><div id="root"></div><script src="/1.js"></script><script src="/2.js"></script><script src="/3.js"></script></body></html>'
    c = by_id(funnel.run(ctx_for(html, "https://app.example/")))
    assert c["contact_path"]["status"] == "unknown" and c["analytics"]["status"] == "unknown"
    assert "whatsapp_button" not in c and "click_to_call" not in c


def test_tag_manager_hides_the_tags_so_no_analytics_verdict_is_given():
    html = "<html><head><title>A</title><script>(function(){/* GTM-ABC123 */})</script></head><body><p>" + "text " * 100 + "</p><a href='tel:+1'>c</a></body></html>"
    assert by_id(funnel.run(ctx_for(html)))["analytics"]["status"] == "info"


def test_forms_are_told_apart():
    search = "<form><input type=search name=q></form>"
    news = "<form><input type=email name=email><button type=submit>go</button></form>"
    login = "<form><input name=user><input type=password name=pw></form>"
    assert funnel._classify(htmlread.read(search, "x").forms[0]) == "search"
    assert funnel._classify(htmlread.read(news, "x").forms[0]) == "signup"
    assert funnel._classify(htmlread.read(login, "x").forms[0]) == "login"


def test_whatsapp_chat_and_booking_are_detected():
    html = ("<html><head><title>A</title><script src='https://embed.tawk.to/x/y'></script></head><body><p>" + "text " * 100 +
            "</p><a href='https://wa.me/911234567890'>WhatsApp</a><a href='https://calendly.com/acme/demo'>Book</a></body></html>")
    c = by_id(funnel.run(ctx_for(html)))
    assert c["whatsapp_button"]["status"] == "pass" and "Tawk.to" in c["chat_widget"]["value"] and "calendly" in c["booking_link"]["value"]


def test_nothing_read_means_unknown_with_the_reason():
    ctx = site.Ctx()
    ctx.refused, ctx.refused_reason = True, "The site refused our automated visit (HTTP 403)"
    c = by_id(funnel.run(ctx))
    assert all(x["status"] == "unknown" for x in c.values()) and "refused" in c["contact_path"]["detail"]


# ---------------------------------------------------------------- speed

def lighthouse(perf=0.42, acc=0.8, weight=6_200_000, field="SLOW"):
    return {"lighthouseResult": {"categories": {"performance": {"score": perf}, "accessibility": {"score": acc}}, "fetchTime": "2026-10-22T00:00:00Z", "lighthouseVersion": "12",
                                 "audits": {"largest-contentful-paint": {"numericValue": 6200, "displayValue": "6.2 s"}, "total-blocking-time": {"numericValue": 900, "displayValue": "900 ms"},
                                            "cumulative-layout-shift": {"numericValue": 0.3, "displayValue": "0.3"}, "total-byte-weight": {"numericValue": weight},
                                            "image-alt": {"score": 0, "scoreDisplayMode": "binary", "title": "Image elements do not have [alt] attributes", "details": {"items": [1, 2, 3]}}}},
            "loadingExperience": {"overall_category": field, "metrics": {"LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 5200}}} if field else {}}


def test_speed_reports_lab_and_field_separately_and_labels_them():
    c = by_id(speed.run("https://acme.com/", call=lambda u: lighthouse()))
    assert c["speed_lab"]["status"] == "issue" and c["speed_lab"]["value"] == "42 / 100" and "vary a few points" in c["speed_lab"]["detail"]
    assert c["speed_field"]["status"] == "issue" and "real Chrome users" in c["speed_field"]["detail"]
    assert c["page_weight"]["status"] == "issue" and c["page_weight"]["value"] == "6.2 MB"
    assert c["accessibility"]["status"] == "warn" and "Automated checks only" in c["accessibility"]["detail"] and "3 elements" in c["accessibility"]["detail"]


def test_no_real_visitor_data_is_unknown_with_the_reason():
    c = by_id(speed.run("https://acme.com/", call=lambda u: lighthouse(perf=0.95, field=None)))
    assert c["speed_lab"]["status"] == "pass" and c["speed_field"]["status"] == "unknown" and "enough real-visitor data" in c["speed_field"]["detail"]


def test_a_busy_google_quota_is_unknown_not_a_slow_site(monkeypatch):
    class R:
        status_code = 429
    monkeypatch.setattr(speed.httpx, "get", lambda *a, **k: R())
    c = by_id(speed.run("https://acme.com/"))
    assert c["speed_lab"]["status"] == "unknown" and "quota is busy" in c["speed_lab"]["detail"]


# ---------------------------------------------------------------- engine + API

@pytest.fixture
def api(monkeypatch):
    engine.JOBS.clear()
    engine._history.clear()
    app = FastAPI()
    app.include_router(router, prefix="/api/raptor/audit")
    who = {"id": "user-1"}
    app.dependency_overrides[get_current_user] = lambda: who["id"]

    def fake_runner(job):
        return {"website": [check("title", "website", "Page title", "pass"), check("meta_description", "website", "Search description", "issue", priority=41, fix="Write one.")],
                "domain_email": [check("dmarc", "domain_email", "DMARC record", "issue", priority=5, fix="Publish DMARC.", raptor="Diagnostics tool")], "funnel": []}
    monkeypatch.setattr(engine, "_default_runner", fake_runner)
    client = TestClient(app)
    client.who = who
    return client


def wait(client, jid, user=None):
    for _ in range(100):
        got = client.get("/api/raptor/audit/" + jid).json()
        if got["status"] != "running":
            return got
        time.sleep(0.05)
    raise AssertionError("audit did not finish")


def body(**kw):
    return {"company": "Acme Robots", "website": "https://www.acme.com/", "city": "Pune", "preset": "b2b", "keywords": ["warehouse robots", "warehouse robots", ""],
            "competitors": ["rival.com", "acme.com", "bad address"][:1], "note": "leads are slow", **kw}


def test_an_audit_runs_and_the_report_orders_findings_by_the_published_rule(api):
    jid = api.post("/api/raptor/audit/start", json=body()).json()["job_id"]
    got = wait(api, jid)
    assert got["status"] == "done"
    r = got["report"]
    assert r["company"] == "Acme Robots" and r["website"] == "www.acme.com" and r["preset"] == "b2b" and r["keywords"] == ["warehouse robots"]
    assert [s["id"] for s in r["sections"]] == ["domain_email", "website"]                 # the B2B preset leads with email trust
    assert [f["id"] for f in r["top_findings"]] == ["dmarc", "meta_description"]
    assert [f["id"] for f in r["fixes"]] == ["dmarc", "meta_description"] and r["fixes"][0]["raptor"] == "Diagnostics tool"
    assert r["score"]["based_on"] == 3 and r["counts"]["issue"] == 2 and r["priority_rule"]


def test_bad_input_is_refused_with_a_plain_message(api):
    assert api.post("/api/raptor/audit/start", json=body(company="  ")).status_code == 400
    r = api.post("/api/raptor/audit/start", json=body(website="http://169.254.169.254/"))
    assert r.status_code == 400 and "website address" in r.json()["detail"]
    assert api.post("/api/raptor/audit/start", json=body(competitors=["not a site"])).status_code == 400


def test_only_the_person_who_started_an_audit_can_read_it(api):
    jid = api.post("/api/raptor/audit/start", json=body()).json()["job_id"]
    wait(api, jid)
    api.who["id"] = "user-2"
    assert api.get("/api/raptor/audit/" + jid).status_code == 404


def test_one_audit_at_a_time_and_a_daily_limit(api, monkeypatch):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(engine, "_default_runner", lambda job: (gate.wait(5), {"website": [], "domain_email": [], "funnel": []})[1])
    first = api.post("/api/raptor/audit/start", json=body())
    assert first.status_code == 200
    second = api.post("/api/raptor/audit/start", json=body())
    assert second.status_code == 429 and "still running" in second.json()["detail"]
    gate.set()
    wait(api, first.json()["job_id"])
    monkeypatch.setattr(engine, "PER_USER_PER_DAY", 1)
    assert api.post("/api/raptor/audit/start", json=body()).status_code == 429


def test_a_crashing_part_never_loses_the_other_sections(monkeypatch):
    monkeypatch.setattr(engine.speed, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(engine.domain, "run", lambda s: [check("dmarc", "domain_email", "DMARC record", "pass")])
    monkeypatch.setattr(engine.site_checks, "run", lambda s: ([check("title", "website", "Page title", "pass")], site.Ctx()))
    monkeypatch.setattr(engine.funnel, "run", lambda c: [check("contact_path", "funnel", "Contact", "pass")])
    monkeypatch.setattr(engine.search, "run", lambda i: ([check("rank_brand", "visibility", "Found by name", "pass")], []))
    monkeypatch.setattr(engine.history, "run", lambda s: [check("wayback_first", "history", "First archived", "info")])
    job = {"inputs": {"company": "A", "site": normalize_site("acme.com")}, "sections": {}, "progress": []}
    res, extras = engine._default_runner(job)
    ids = {c["id"] for sec in res.values() for c in sec}
    assert {"title", "dmarc", "contact_path", "rank_brand", "wayback_first"} <= ids and any(c["status"] == "unknown" for c in res["website"])
    assert "competitors" not in extras


def test_a_crashing_search_part_is_unknown_and_the_rest_survives(monkeypatch):
    monkeypatch.setattr(engine.speed, "run", lambda *a, **k: [])
    monkeypatch.setattr(engine.domain, "run", lambda s: [])
    monkeypatch.setattr(engine.site_checks, "run", lambda s: ([], site.Ctx()))
    monkeypatch.setattr(engine.funnel, "run", lambda c: [])
    monkeypatch.setattr(engine.history, "run", lambda s: [])
    monkeypatch.setattr(engine.search, "run", lambda i: (_ for _ in ()).throw(RuntimeError("boom")))
    res, _ = engine._default_runner({"inputs": {"company": "A", "site": normalize_site("acme.com")}, "sections": {}, "progress": []})
    assert res["visibility"][0]["status"] == "unknown"

"""tests/test_audit_visibility.py: the search-based and history parts of the Company Audit, and the competitor comparison. No network.

Same rule as test_audit.py: a finding is only shown if it was measured; a failed or exhausted search is `unknown`, never a problem."""
import pytest

from raptor.audit import compare, engine, history, search
from raptor.audit.common import check, normalize_site

from tests.test_audit import api, body, by_id, wait  # noqa: F401  (api is a fixture)


def serp_page(links, ads=(), pack=()):
    return {"organic_results": [{"position": i, "link": l, "title": "t%d" % i} for i, l in enumerate(links, 1)],
            "ads": [{"link": a} for a in ads], "local_results": {"places": list(pack)}}


class FakeSerp:
    def __init__(self, brand=None, keywords=None, maps=None, news=None):
        self.brand, self.keywords, self.maps, self.news, self.calls = brand, keywords or {}, maps, news, []

    def __call__(self, params):
        self.calls.append(params)
        if params["engine"] == "google_maps":
            if isinstance(self.maps, Exception):
                raise self.maps
            return self.maps or {}
        if params["engine"] == "google_news":
            return self.news or {}
        got = self.brand if params["q"] == "Acme Robots" else self.keywords.get(params["q"], {})
        if isinstance(got, Exception):
            raise got
        return got


def sinputs(**kw):
    return {"company": "Acme Robots", "site": normalize_site("www.acme.com"), "city": "Pune, Maharashtra, India", "keywords": ["warehouse robots"], **kw}


def test_search_analysis_finds_the_position_the_pack_and_the_advertisers():
    data = serp_page(["https://rival.com/a", "https://www.acme.com/x", "https://acme.com/y"], ads=["https://ads.rival.com/p", "https://acme.com/ad"],
                     pack=[{"title": "Rival", "website": "https://rival.com"}, {"title": "Acme Robots", "website": "https://acme.com", "rating": 4.5, "reviews": 30}])
    a = search.analyse(data, "acme.com", "Acme Robots")
    assert a["position"] == 2 and a["positions"]["rival.com"] == 1 and a["map_position"] == 2 and a["own_ad"] and "rival.com" in a["advertisers"][0]


def test_rankings_record_the_search_the_place_and_the_date():
    serp = FakeSerp(brand=serp_page(["https://acme.com/"]), keywords={"warehouse robots": serp_page(["https://rival.com/", "https://x.com/"] + ["https://f%d.com/" % i for i in range(5)])},
                    maps={"local_results": []}, news={})
    checks, rankings = search.run(sinputs(), serp)
    c = by_id(checks)
    assert c["rank_brand"]["status"] == "pass" and c["rank_brand"]["value"] == "#1"
    kw = c["rank_warehouse_robots"]
    assert kw["status"] == "issue" and kw["value"] == "not in the top 20" and "Pune, Maharashtra, India" in kw["detail"] and "Rankings change by place and day" in kw["detail"]
    assert kw["evidence"]["query"] == "warehouse robots" and kw["evidence"]["date"]
    assert serp.calls[0]["location"] == "Pune, Maharashtra, India" and serp.calls[0]["num"] == 20
    assert len(rankings) == 2


def test_only_the_asked_keywords_are_searched_and_with_none_a_hint_is_shown():
    serp = FakeSerp(brand=serp_page(["https://acme.com/"]))
    checks, rankings = search.run(sinputs(keywords=[]), serp)
    assert [r["kind"] for r in rankings] == ["brand"] and by_id(checks)["keywords_hint"]["status"] == "info"
    assert [c["q"] for c in serp.calls if c["engine"] == "google"] == ["Acme Robots"]


def test_a_top_three_ranking_passes_and_a_lower_one_is_a_warning():
    top3 = serp_page(["https://a.com", "https://b.com", "https://www.acme.com/"])
    low = serp_page(["https://f%d.com" % i for i in range(7)] + ["https://acme.com/"])
    assert by_id(search.run(sinputs(), FakeSerp(brand=top3, keywords={"warehouse robots": top3}))[0])["rank_warehouse_robots"]["status"] == "pass"
    c = by_id(search.run(sinputs(), FakeSerp(brand=top3, keywords={"warehouse robots": low}))[0])["rank_warehouse_robots"]
    assert c["status"] == "warn" and c["value"] == "#8"


def test_a_failing_or_exhausted_search_is_unknown_never_a_problem():
    down = FakeSerp(brand=search.SearchUnavailable("The search service answered HTTP 429."), maps=search.SearchUnavailable("busy"))
    checks, rankings = search.run(sinputs(), down)
    c = by_id(checks)
    assert rankings == [] and c["rank_brand"]["status"] == "unknown" and "429" in c["rank_brand"]["detail"] and c["google_reviews"]["status"] == "unknown"
    assert not [x for x in checks if x["status"] in ("issue", "warn")]


def test_the_daily_search_allowance_is_enforced(monkeypatch):
    monkeypatch.setenv("SERPAPI_KEY", "k")
    monkeypatch.setattr(search, "DAILY_QUOTA", 1)
    search._quota.update({"day": None, "used": 0})
    monkeypatch.setattr(search.httpx, "get", lambda *a, **k: type("R", (), {"status_code": 200, "json": lambda self: {"organic_results": []}})())
    search._serp({"engine": "google", "q": "x"})
    with pytest.raises(search.SearchUnavailable) as e:
        search._serp({"engine": "google", "q": "y"})
    assert "allowance" in str(e.value)


def test_without_a_search_key_it_says_so(monkeypatch):
    monkeypatch.delenv("SERPAPI_KEY", raising=False)
    with pytest.raises(search.SearchUnavailable):
        search._serp({"engine": "google", "q": "x"})


def test_reviews_are_shown_only_for_a_confident_match():
    maps = {"local_results": [{"title": "Acme Robots Pvt Ltd", "website": "https://www.acme.com/", "rating": 4.6, "reviews": 120}, {"title": "Other", "website": "https://x.com", "rating": 1.0, "reviews": 3}]}
    c = by_id(search.run(sinputs(keywords=[]), FakeSerp(brand=serp_page([]), maps=maps))[0])["google_reviews"]
    assert c["status"] == "pass" and c["value"] == "4.6 stars from 120 reviews" and "Matched by its website" in c["detail"]
    named = {"local_results": [{"title": "Acme Robots", "rating": 3.8, "reviews": 9}]}                       # exact name only: shown but flagged
    c = by_id(search.run(sinputs(keywords=[]), FakeSerp(brand=serp_page([]), maps=named))[0])["google_reviews"]
    assert c["status"] == "warn" and "please confirm" in c["detail"] and c["evidence"]["matched_by"] == "name"
    other = {"local_results": [{"title": "Acme Robotics Inc", "website": "https://acmerobotics.us", "rating": 4.9, "reviews": 800}]}     # a look-alike elsewhere: never shown
    c = by_id(search.run(sinputs(keywords=[]), FakeSerp(brand=serp_page([]), maps=other))[0])["google_reviews"]
    assert c["status"] == "unknown" and "matched" in c["detail"]


def test_low_ratings_are_issues_with_the_numbers_shown():
    maps = {"place_results": {"title": "Acme Robots", "website": "https://acme.com", "rating": 3.2, "reviews": 4}}
    c = by_id(search.run(sinputs(keywords=[]), FakeSerp(brand=serp_page([]), maps=maps))[0])["google_reviews"]
    assert c["status"] == "issue" and "only 4 reviews" in c["detail"]


def test_news_lists_what_was_found_with_sources():
    news = {"news_results": [{"title": "Acme opens plant", "link": "https://n.example/1", "source": {"name": "The Daily"}, "date": "2 days ago"}]}
    c = by_id(search.run(sinputs(keywords=[]), FakeSerp(brand=serp_page([]), maps={}, news=news))[0])["news"]
    assert c["status"] == "info" and "The Daily" in c["detail"] and c["evidence"][0]["link"] == "https://n.example/1"


def test_history_reports_a_lower_bound_and_never_calls_silence_a_problem():
    rows = lambda kind: {"first": ([["20120304000000", "d"]], ""), "latest": ([["20260915010101", "d"]], ""), "recent": ([["x", "a"], ["y", "b"], ["z", "c"]], "")}[kind]
    c = by_id(history.run(normalize_site("acme.com"), rows=rows))
    assert c["wayback_first"]["value"] == "2012-03-04" and "3 different version(s); latest 2026-09-15" in c["wayback_changes"]["value"]
    assert "may be higher" in c["wayback_changes"]["detail"]
    c = by_id(history.run(normalize_site("acme.com"), rows=lambda kind: ([], "")))
    assert c["wayback_changes"]["status"] == "info" and "did not visit" in c["wayback_changes"]["detail"] and c["wayback_first"]["value"] == "never archived"
    assert all(x["status"] == "unknown" for x in history.run(normalize_site("acme.com"), rows=lambda kind: (None, "timeout")))


def fake_profile(site_):
    if site_["host"] == "blocked.com":
        raise RuntimeError("refused")
    ok = lambda cid, st="pass", v=None: check(cid, "x", cid, st, value=v)
    return {c["id"]: c for c in [ok("https_works"), ok("dmarc", "issue", "missing"), ok("spf"), ok("contact_path", "pass", "enquiry form")]}


def test_the_comparison_runs_the_same_measures_and_a_failure_is_unknown_not_zero():
    mine = {c["id"]: c for c in [check("https_works", "x", "h", "pass"), check("dmarc", "x", "d", "pass", value="p=reject")]}
    rankings = [{"kind": "keyword", "query": "warehouse robots", "location": "Pune", "date": "22 Oct 2026", "positions": {"acme.com": 4, "rival.com": 1}}]
    inputs = {"company": "Acme", "site": normalize_site("acme.com"), "competitors": [normalize_site("rival.com"), normalize_site("blocked.com")]}
    t = compare.build(inputs, mine, rankings, profile_fn=fake_profile)
    rows = {r["host"]: r for r in t["rows"]}
    assert rows["acme.com"]["is_company"] and rows["acme.com"]["cells"]["dmarc"]["value"] == "p=reject"
    assert rows["acme.com"]["cells"]["viewport"]["status"] == "unknown"                       # not measured for this row: unknown, not a failure
    assert rows["rival.com"]["cells"]["dmarc"]["status"] == "issue" and rows["rival.com"]["ranks"] == {"warehouse robots": 1}
    assert all(c["status"] == "unknown" for c in rows["blocked.com"]["cells"].values()) and rows["blocked.com"]["ranks"] == {"warehouse robots": None}
    assert rows["acme.com"]["ranks"]["warehouse robots"] == 4 and t["searched_from"] == "Pune" and "never counted against" in t["note"]


def test_the_finished_report_carries_the_comparison_and_the_rankings(api, monkeypatch):
    table = {"columns": [], "rows": [], "queries": []}
    monkeypatch.setattr(engine, "_default_runner", lambda job: ({"website": [check("title", "website", "Page title", "pass")]}, {"competitors": table, "rankings": [{"query": "q"}]}))
    jid = api.post("/api/raptor/audit/start", json=body()).json()["job_id"]
    r = wait(api, jid)["report"]
    assert r["competitors"] == table and r["rankings"] == [{"query": "q"}]


def test_a_competitor_whose_site_cannot_be_reached_gets_unknown_cells_and_a_note_not_dns_verdicts():
    def profile_fn(s):
        return {"site_reachable": check("site_reachable", "website", "Website reachable", "issue", detail="The address gone.example does not lead to a website: its name does not resolve.")}
    inputs = {"company": "Acme", "site": normalize_site("acme.com"), "competitors": [normalize_site("gone.example")]}
    t = compare.build(inputs, {}, [], profile_fn=profile_fn)
    row = [r for r in t["rows"] if r["host"] == "gone.example"][0]
    assert all(c["status"] == "unknown" for c in row["cells"].values()) and "does not lead to a website" in row["note"]


def test_the_real_profile_stops_at_a_dead_site_instead_of_judging_its_empty_dns(monkeypatch):
    dead = check("site_reachable", "website", "Website reachable", "issue")
    monkeypatch.setattr(compare.site_checks, "run", lambda s, light=False: ([dead], None))
    monkeypatch.setattr(compare.domain, "run", lambda *a, **k: pytest.fail("DNS must not be judged for a site that cannot be reached"))
    assert list(compare.profile(normalize_site("gone.example"))) == ["site_reachable"]

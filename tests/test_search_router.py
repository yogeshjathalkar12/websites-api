"""tests/test_search_router.py: web search for the desktop app (raptor/search_router.py). No network: SerpAPI is faked."""
import os

for _name in ("EMAIL_TRACKING_SIGNING_SECRET", "UNSUBSCRIBE_SIGNING_SECRET"):   # the app refuses to import without these; any value works for a test
    os.environ.setdefault(_name, "x" * 40)

import pytest
import requests
from fastapi import HTTPException
from fastapi.testclient import TestClient

from tests.test_whatsapp_crm_dispatch import ACCOUNT  # noqa: F401,I001  (importing it sets the encryption keys the app needs before main is imported)
from raptor import search_router as sr


class Reply:
    def __init__(self, body=None, fail=False):
        self._body, self._fail = body or {"organic_results": [{"title": "Acme", "link": "https://acme.example", "snippet": "robots"}]}, fail

    def json(self):
        return self._body

    def raise_for_status(self):
        if self._fail:
            raise requests.HTTPError("502")


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SERPAPI_KEY", "serp-key")
    sr._calls.clear()
    seen = []
    monkeypatch.setattr(sr.requests, "get", lambda url, params=None, timeout=None: (seen.append((url, params, timeout)), Reply())[1])
    return seen


def test_a_signed_in_user_gets_the_search_results_and_the_key_goes_only_to_serpapi(env):
    out = sr.search("warehouse robots pune", user_id="u1")
    assert out["organic_results"][0]["link"] == "https://acme.example"
    url, params, timeout = env[0]
    assert url == sr.SERPAPI_URL and params == {"q": "warehouse robots pune", "api_key": "serp-key"} and timeout


def test_an_empty_or_huge_query_is_refused(env):
    for q in ("", "   ", "x" * 501):
        with pytest.raises(HTTPException) as e:
            sr.search(q, user_id="u1")
        assert e.value.status_code == 400
    assert env == []


def test_a_server_without_the_key_says_so_and_calls_nothing(env, monkeypatch):
    monkeypatch.delenv("SERPAPI_KEY")
    with pytest.raises(HTTPException) as e:
        sr.search("x", user_id="u1")
    assert e.value.status_code == 500 and env == []


def test_a_failing_search_service_gives_a_clean_502(monkeypatch):
    monkeypatch.setattr(sr.requests, "get", lambda *a, **k: Reply(fail=True))
    with pytest.raises(HTTPException) as e:
        sr.search("x", user_id="u1")
    assert e.value.status_code == 502

    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(sr.requests, "get", boom)
    with pytest.raises(HTTPException) as e:
        sr.search("x", user_id="u1")
    assert e.value.status_code == 502


def test_one_user_cannot_search_more_than_the_limit_per_minute_and_others_are_not_affected():
    for _ in range(sr.PER_MINUTE):
        sr.search("x", user_id="busy")
    with pytest.raises(HTTPException) as e:
        sr.search("x", user_id="busy")
    assert e.value.status_code == 429
    assert sr.search("x", user_id="someone-else")["organic_results"]


def test_the_daily_limit_applies_across_minutes(monkeypatch):
    clock = {"t": 1000.0}
    for i in range(sr.PER_DAY):
        sr._check_limits("heavy", clock["t"] + i * 61)          # one a minute-and-a-bit: never trips the per-minute rule
    with pytest.raises(HTTPException) as e:
        sr._check_limits("heavy", clock["t"] + sr.PER_DAY * 61 - 1)
    assert e.value.status_code == 429 and "Daily" in e.value.detail


def test_the_route_needs_a_signed_in_user_and_main_mounts_it(env):
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(sr.router, prefix="/api/raptor/search")
    client = TestClient(app)
    assert client.get("/api/raptor/search", params={"query": "x"}).status_code in (401, 403)           # no token
    app.dependency_overrides[sr.get_current_user] = lambda: "u9"
    r = client.get("/api/raptor/search", params={"query": "x"})
    assert r.status_code == 200 and r.json()["organic_results"][0]["title"] == "Acme"

    main_source = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py"), encoding="utf-8").read()
    assert 'include_router(raptor_search_router, prefix="/api/raptor/search"' in main_source


def test_a_location_and_country_are_passed_to_google_and_cleaned(env):
    sr.search("dental clinics in Pune", location="  Pune,   Maharashtra, India ", gl="IN", user_id="u1")
    assert env[0][1] == {"q": "dental clinics in Pune", "api_key": "serp-key", "location": "Pune, Maharashtra, India", "gl": "in"}


def test_a_bad_country_code_or_a_huge_location_is_not_trusted(env):
    sr.search("clinics", location="x" * 500, gl="india!", user_id="u1")
    params = env[0][1]
    assert "gl" not in params and len(params["location"]) == sr.MAX_LOCATION
    sr.search("clinics", user_id="u1")
    assert env[1][1] == {"q": "clinics", "api_key": "serp-key"}                    # no area: exactly as before

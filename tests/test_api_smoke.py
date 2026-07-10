"""
tests/test_api_smoke.py — exercises the actual FastAPI app via TestClient.

Two things this catches that unit tests can't:
  1. main.py actually wires every router in correctly (import errors,
     prefix typos, etc. surface immediately as a failed test, not a
     surprise on Render after deploy).
  2. Every endpoint that's SUPPOSED to require a Bearer token or a
     shared secret still does. This is the most valuable test class here:
     if someone later removes a `Depends(get_current_user)` by accident
     while refactoring, this fails loudly instead of shipping an open
     endpoint to production.
"""
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


# ── Public endpoints: should all return 200 ────────────────────────────
PUBLIC_STATUS_ENDPOINTS = [
    "/",
    "/api/raptor/status",
    "/api/raptor/chronos/status",
    "/api/raptor/kmeans/status",
    "/api/raptor/montecarlo/status",
    "/api/raptor/resolver/status",
    "/api/raptor/spintax/status",
    "/api/raptor/threader/status",
    "/api/raptor/vad/status",
    "/api/raptor/video/status",
    "/api/raptor/crm/status",
]


@pytest.mark.parametrize("path", PUBLIC_STATUS_ENDPOINTS)
def test_status_endpoints_are_reachable(path):
    resp = client.get(path)
    assert resp.status_code == 200


def test_tracking_pixel_is_public_and_returns_an_image():
    """The one endpoint that MUST stay public: email clients fetch it
    with no auth header of any kind."""
    resp = client.get("/api/raptor/track/anycampaign123.png")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"


def test_tracking_pixel_rejects_malformed_campaign_id():
    resp = client.get("/api/raptor/track/bad id with spaces.png")
    assert resp.status_code == 400


# ── JWT-protected endpoints: every one of these must reject a request
#    with no Authorization header. (method, path, json_body_or_None)
PROTECTED_ENDPOINTS = [
    ("get", "/api/raptor/verify-email?address=test@example.com", None),
    ("get", "/api/raptor/generate-tracker?campaign_id=test123", None),
    ("get", "/api/raptor/campaign-opens", None),
    ("post", "/api/raptor/chronos/resolve", {"place": "Austin, Texas"}),
    ("get", "/api/raptor/chronos/scheduled", None),
    ("post", "/api/raptor/kmeans/cluster", {"rows": [{"x": 1}], "fields": ["x"], "k": 2}),
    ("get", "/api/raptor/kmeans/history", None),
    ("post", "/api/raptor/montecarlo/simulate", {"deals": [{"value": 100, "probability": 0.5}]}),
    ("get", "/api/raptor/montecarlo/history", None),
    ("get", "/api/raptor/resolver/site-key", None),
    ("post", "/api/raptor/resolver/ranges/upload", {"ranges": [{"cidr": "10.0.0.0/8", "company_name": "Test"}]}),
    ("get", "/api/raptor/resolver/resolve?ip=1.1.1.1", None),
    ("get", "/api/raptor/resolver/visits", None),
    ("post", "/api/raptor/spintax/compile", {"template": "hi"}),
    ("post", "/api/raptor/spintax/queue", {"template": "hi", "campaign_id": "test"}),
    ("get", "/api/raptor/spintax/queue/test", None),
    ("post", "/api/raptor/threader/scan-threads", {"imap_host": "imap.example.com", "username": "a@b.com", "app_password": "x"}),
    ("get", "/api/raptor/threader/history", None),
    ("post", "/api/raptor/vad/log-result", {"call_id": "c1", "original_duration_sec": 10, "compressed_duration_sec": 5}),
    ("post", "/api/raptor/vad/process-batch", {"call_id": "c1", "wav_base64": "AA=="}),
    ("get", "/api/raptor/vad/history", None),
    ("post", "/api/raptor/video/verify-scrub", {"compressed_video_base64": "AA=="}),
    ("post", "/api/raptor/video/log-result", {"video_id": "v1", "original_size_bytes": 100, "compressed_size_bytes": 50}),
    ("get", "/api/raptor/video/history", None),
]


@pytest.mark.parametrize("method,path,body", PROTECTED_ENDPOINTS)
def test_protected_endpoints_reject_unauthenticated_requests(method, path, body):
    resp = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
    assert resp.status_code in (401, 403), f"{method.upper()} {path} should require auth, got {resp.status_code}"


# ── CRM automation engine: shared-secret protected, not JWT ────────────
def test_crm_run_rejects_missing_secret():
    resp = client.post("/api/raptor/crm/run")
    assert resp.status_code == 401


def test_crm_run_rejects_wrong_secret():
    resp = client.post("/api/raptor/crm/run", headers={"X-Automation-Secret": "definitely-wrong"})
    assert resp.status_code == 401


def test_crm_run_now_rejects_missing_secret():
    resp = client.post("/api/raptor/crm/some-automation-id/run-now")
    assert resp.status_code == 401


# ── Resolver's public beacon: regression tests for the site_key fix ────
def test_track_visit_is_public_but_requires_site_key():
    """Public by necessity (visitors aren't logged in), but must reject
    a call with no site_key rather than silently trusting the caller."""
    resp = client.post("/api/raptor/resolver/track-visit", json={"ip": "1.2.3.4"})
    assert resp.status_code == 400


def test_track_visit_rejects_legacy_site_user_id_param():
    """The old (vulnerable) version of this endpoint trusted a raw
    site_user_id passed straight in the body. Proves that param name has
    no special power anymore -- site_key is the only thing that works."""
    resp = client.post(
        "/api/raptor/resolver/track-visit",
        json={"site_user_id": "11111111-1111-1111-1111-111111111111", "ip": "1.2.3.4"},
    )
    assert resp.status_code == 400


def test_track_visit_rejects_unknown_site_key():
    resp = client.post(
        "/api/raptor/resolver/track-visit",
        json={"site_key": "not-a-real-key", "ip": "1.2.3.4"},
    )
    # 401 (bad key) or 500 (no Supabase configured in CI) are both
    # acceptable here -- what must NOT happen is a 200 with a match.
    assert resp.status_code in (401, 500)

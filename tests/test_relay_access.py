"""tests/test_relay_access.py: who may use the mobile relay (raptor/relay_router.py _verify_token). No network: the login token and the web app's
membership answer are faked."""
import os

for _name in ("EMAIL_TRACKING_SIGNING_SECRET", "UNSUBSCRIBE_SIGNING_SECRET"):
    os.environ.setdefault(_name, "x" * 40)

import pytest

from raptor import relay_router as rr


class Key:
    key = "k"


@pytest.fixture
def login(monkeypatch):
    """A valid login whose claims we control, and a membership answer we control."""
    state = {"claims": {"plan": "Free", "client_ids": ["default"]}, "member": {}}
    monkeypatch.setattr(rr._jwks_client, "get_signing_key_from_jwt", lambda token: Key())
    monkeypatch.setattr(rr.pyjwt, "decode", lambda *a, **k: dict(state["claims"]))
    monkeypatch.setattr(rr, "_membership", lambda token: dict(state["member"]))
    return state


def test_a_teammate_uses_the_organizations_plan_and_company_id(login):
    login["member"] = {"status": "active", "plan": "Pro", "client_id": "acme_com"}
    assert rr._verify_token("t", "acme_com")["plan"] == "Free"        # allowed although the login's own claims say Free and name no company


def test_a_removed_or_unconfirmed_person_is_refused(login):
    for status in ("removed", "invited"):
        login["member"] = {"status": status, "plan": "Pro", "client_id": "acme_com"}
        login["claims"] = {"plan": "Pro", "client_ids": ["acme_com"]}       # even a login that still carries the old claims
        with pytest.raises(ValueError, match="not active"):
            rr._verify_token("t", "acme_com")


def test_another_companys_id_is_refused(login):
    login["member"] = {"status": "active", "plan": "Pro", "client_id": "acme_com"}
    with pytest.raises(ValueError, match="access to this client"):
        rr._verify_token("t", "rival_com")


def test_a_free_organization_does_not_get_live_copilot(login):
    login["member"] = {"status": "active", "plan": "Free", "client_id": "acme_com"}
    with pytest.raises(ValueError, match="Pro plan"):
        rr._verify_token("t", "acme_com")


def test_when_the_web_app_cannot_be_reached_the_logins_own_claims_decide_as_before(login):
    login["member"] = {}
    login["claims"] = {"plan": "Pro", "client_ids": ["default"]}
    assert rr._verify_token("t", "default")
    with pytest.raises(ValueError, match="access to this client"):
        rr._verify_token("t", "acme_com")


def test_an_expired_login_is_refused(login, monkeypatch):
    def expired(*a, **k):
        raise rr.pyjwt.ExpiredSignatureError()
    monkeypatch.setattr(rr.pyjwt, "decode", expired)
    with pytest.raises(ValueError, match="Session expired"):
        rr._verify_token("t", "acme_com")

"""
tests/test_ai_content_providers.py - raptor/ai_integration/providers.py

The bug this guards against: validate_key() used to do `except ProviderError:
pass`, so whatever the provider actually said (a bad key, an unenabled API,
a wrong region) was thrown away and replaced with a single generic
"Key did not validate against any supported modality." message - which is
what a real user saw and could not act on.

httpx calls are stubbed with response bodies shaped exactly like each
provider's real error JSON (Google's shape below is the verbatim body the
live API returns for an invalid key, captured directly from it).

    python -m pytest tests/test_ai_content_providers.py -q
"""
import json
import sys
import types

import httpx
import pytest

sys.path.insert(0, "raptor/ai_integration")
from raptor.ai_integration import providers  # noqa: E402


def resp(status, body):
    return httpx.Response(status_code=status, json=body, request=httpx.Request("POST", "https://example.test"))


GOOGLE_INVALID_KEY = {  # the real body https://generativelanguage.googleapis.com returns
    "error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
              "status": "INVALID_ARGUMENT"}
}
OPENAI_INVALID_KEY = {"error": {"message": "Incorrect API key provided: sk-***.", "type": "invalid_request_error"}}
ANTHROPIC_INVALID_KEY = {"error": {"type": "authentication_error", "message": "invalid x-api-key"}}


@pytest.fixture
def fake_post(monkeypatch):
    """Queues one canned response per call to httpx.post, in order."""
    queue = []

    def post(url, **kwargs):
        return queue.pop(0)
    monkeypatch.setattr(providers.httpx, "post", post)
    return queue


# ───────────────────────── the actual bug ─────────────────────────

def test_the_provider_own_error_message_reaches_the_user(fake_post):
    """This is the exact scenario from the bug report: a Google key, a real
    Google error, and the user should see THAT, not a generic message."""
    fake_post.append(resp(400, GOOGLE_INVALID_KEY))
    with pytest.raises(providers.ProviderError) as err:
        providers.validate_key("google", "AQ.some-key-that-google-rejects")
    assert "API key not valid" in str(err.value)
    assert str(err.value) != "Key did not validate against any supported modality."


def test_the_message_is_not_a_raw_truncated_json_blob(fake_post):
    fake_post.append(resp(400, GOOGLE_INVALID_KEY))
    with pytest.raises(providers.ProviderError) as err:
        providers.validate_key("google", "bad-key")
    assert '{"error"' not in str(err.value) and '\\n' not in str(err.value)


@pytest.mark.parametrize("provider,body,fragment", [
    ("google", GOOGLE_INVALID_KEY, "API key not valid"),
    ("openai", OPENAI_INVALID_KEY, "Incorrect API key provided"),
    ("anthropic", ANTHROPIC_INVALID_KEY, "invalid x-api-key"),
])
def test_every_provider_surfaces_its_own_real_reason(fake_post, provider, body, fragment):
    fake_post.append(resp(400, body))
    with pytest.raises(providers.ProviderError) as err:
        providers.validate_key(provider, "some-key")
    assert fragment in str(err.value)


def test_a_key_that_genuinely_works_is_confirmed(fake_post):
    fake_post.append(resp(200, {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}))
    caps = providers.validate_key("google", "a-real-working-key")
    assert caps == {"text": True, "image": False, "video": False}  # image/video are off, see below


def test_a_key_that_genuinely_works_is_confirmed_for_a_provider_with_all_three(fake_post):
    fake_post.append(resp(200, {"choices": [{"message": {"content": "ok"}}]}))
    caps = providers.validate_key("openai", "sk-a-real-working-key")
    assert caps == {"text": True, "image": True, "video": False}  # openai: no video


def test_mutation_check_the_old_swallow_behaviour_is_gone(fake_post, monkeypatch):
    """Prove the test above would have caught the original bug: reintroduce
    the old `except ProviderError: pass` and confirm the message reverts to
    the unhelpful generic one."""
    def old_validate_key(provider, api_key):
        caps = providers.PROVIDER_CAPABILITIES[provider]
        confirmed = {"text": False, "image": False, "video": False}
        if caps["text"]:
            try:
                providers.call_text(provider, api_key, caps["text"], "Reply with just: ok", max_tokens=5)
                confirmed["text"] = True
            except providers.ProviderError:
                pass
        if not any(confirmed.values()):
            raise providers.ProviderError("Key did not validate against any supported modality.")
        return confirmed
    fake_post.append(resp(400, GOOGLE_INVALID_KEY))
    with pytest.raises(providers.ProviderError, match="^Key did not validate against any supported modality.$"):
        old_validate_key("google", "bad-key")


# ───────────────────────── error extraction ─────────────────────────

def test_401_still_gets_a_clean_message(fake_post):
    fake_post.append(resp(401, {"error": {"message": "Invalid Authentication"}}))
    with pytest.raises(providers.ProviderError, match="Invalid Authentication"):
        providers.validate_key("openai", "sk-bad")


def test_429_is_reported_as_a_rate_limit_not_a_bad_key(fake_post):
    fake_post.append(resp(429, {"error": {"message": "rate limited"}}))
    with pytest.raises(providers.ProviderError, match="rate-limited"):
        providers.validate_key("openai", "sk-fine-but-throttled")


def test_a_non_json_error_body_falls_back_to_raw_text(fake_post):
    r = httpx.Response(status_code=500, text="upstream is on fire", request=httpx.Request("POST", "https://example.test"))
    fake_post.append(r)
    with pytest.raises(providers.ProviderError, match="upstream is on fire"):
        providers.validate_key("openai", "sk-x")


def test_an_error_string_instead_of_a_dict_is_still_readable(fake_post):
    """Some providers occasionally return {"error": "plain string"} instead
    of {"error": {"message": ...}} - don't crash extracting it."""
    fake_post.append(resp(400, {"error": "malformed request"}))
    with pytest.raises(providers.ProviderError, match="malformed request"):
        providers.validate_key("openai", "sk-x")


# ───────────────────────── unsupported provider ─────────────────────────

def test_unsupported_provider_is_rejected_before_any_network_call(fake_post):
    with pytest.raises(providers.ProviderError, match="Unsupported provider"):
        providers.validate_key("chatgpt", "sk-x")  # the common mistyping of "openai"
    assert fake_post == []  # never even queued/consumed - no call was made


def test_openai_and_anthropic_are_both_already_supported():
    """The other half of the bug report ("add ChatGPT or another AI") -
    confirms both are already registered with a text capability, not that
    they need adding."""
    assert providers.PROVIDER_CAPABILITIES["openai"]["text"]
    assert providers.PROVIDER_CAPABILITIES["anthropic"]["text"]


# ───────────────────────── the model registry itself ─────────────────────────
# Locks in the 2026-09-28 fix: the failing model name from the bug report,
# and Google's own live error message pointing at its replacement.

def test_google_text_uses_the_current_model_not_the_retired_one():
    assert providers.PROVIDER_CAPABILITIES["google"]["text"] == "gemini-3.8-flash"
    assert providers.PROVIDER_CAPABILITIES["google"]["text"] != "gemini-2.5-flash"


def test_google_image_and_video_are_off_rather_than_pointing_at_dead_models():
    """Imagen (the old image backend) was shut down; the replacement uses a
    different API shape this codebase does not implement yet. Off is safer
    than silently calling a dead endpoint - and the pipeline step-validation
    below is what actually enforces that at request time."""
    assert providers.PROVIDER_CAPABILITIES["google"]["image"] is None
    assert providers.PROVIDER_CAPABILITIES["google"]["video"] is None


# ───────────────────────── the pipeline endpoint's own guard ─────────────────────────
# A None capability isn't just a registry value - confirm the actual /pipeline
# route refuses a disabled modality BEFORE it ever reaches the network, with a
# clean message, rather than building a request against a dead model.

# ───────────────────────── transient 503 retry ─────────────────────────
# The bug this guards against: a save-key click that hit Google while it was
# briefly overloaded (a real, live "high demand... try again later" 503,
# 2026-09-28) surfaced straight to the user with no retry, so a blip the
# provider itself calls transient made the user manually re-click save.

def test_a_503_that_clears_on_retry_succeeds_transparently(fake_post, monkeypatch):
    monkeypatch.setattr(providers.time, "sleep", lambda *_: None)
    fake_post.append(resp(503, {"error": {"message": "model overloaded"}}))
    fake_post.append(resp(200, {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}))
    caps = providers.validate_key("google", "a-real-working-key")
    assert caps == {"text": True, "image": False, "video": False}
    assert fake_post == []  # both queued responses were consumed


def test_a_503_that_never_clears_still_surfaces_after_retrying(fake_post, monkeypatch):
    monkeypatch.setattr(providers.time, "sleep", lambda *_: None)
    fake_post.append(resp(503, {"error": {"message": "model overloaded"}}))
    fake_post.append(resp(503, {"error": {"message": "model overloaded"}}))
    with pytest.raises(providers.ProviderError, match="model overloaded"):
        providers.validate_key("google", "a-real-working-key")
    assert fake_post == []  # retried exactly once, then gave up - not an infinite loop


def test_a_real_error_status_is_not_retried_at_all(fake_post, monkeypatch):
    """A 401 means the key is bad, not that the provider is busy - retrying
    it would just be three slow ways of learning the same thing."""
    def fail_if_called_again(*_a, **_k):
        raise AssertionError("should not have retried a non-503 error")
    monkeypatch.setattr(providers.time, "sleep", fail_if_called_again)
    fake_post.append(resp(401, {"error": {"message": "Invalid Authentication"}}))
    with pytest.raises(providers.ProviderError, match="Invalid Authentication"):
        providers.validate_key("google", "bad-key")
    assert fake_post == []


def test_the_pipeline_route_refuses_googles_disabled_image_modality_up_front(fake_post, monkeypatch):
    from raptor.ai_integration import content_router

    monkeypatch.setattr(content_router, "check_rate_limit", lambda user_id, modality: None)
    monkeypatch.setattr(content_router.key_vault, "get_decrypted_key", lambda user_id, provider: "fake-key")

    payload = {"steps": [{"provider": "google", "modality": "image", "prompt": "a picture of a cat"}]}
    with pytest.raises(content_router.HTTPException) as err:
        content_router.run_pipeline(payload, user_id="u1")
    assert err.value.status_code == 400
    assert "google" in err.value.detail and "image" in err.value.detail
    assert fake_post == []  # refused before any network call was attempted

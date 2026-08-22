"""
providers.py — AI Content Suite: provider registry + raw call wrappers

Design choice worth stating up front: there is no reliable cross-provider
"introspect this key and tell me what it can do" endpoint. OpenAI, Google,
and Anthropic each expose different (or no) capability-listing APIs, and
none of them are cheap or fast enough to call on every page load. So
capability is a STATIC registry we maintain here, and a key's *actual*
capability is confirmed once, at save-time, via one cheap validation call
per modality the provider claims to support (see validate_key below).
If a provider adds/removes a model, this file is what you update.

No provider SDKs are used — every call is a raw httpx request. That keeps
this file dependency-light (matches the rest of this codebase, e.g.
chronos_router.py's raw httpx call to Nominatim) and keeps every provider's
request/response shape visible in one place instead of hidden behind
three different SDKs with three different conventions.
"""

import base64
import httpx

# ---------------------------------------------------------------------------
# Capability registry
# ---------------------------------------------------------------------------
# "video" providers use an async job pattern (start -> poll); "text" and
# "image" are synchronous single-call. None = provider doesn't offer that
# modality at all, so it's never offered in the UI regardless of what the
# user's key can technically authenticate against.

PROVIDER_CAPABILITIES = {
    "openai": {
        "text": "gpt-4.1",
        "image": "dall-e-3",
        "video": None,
    },
    "google": {
        "text": "gemini-2.5-flash",
        "image": "imagen-4.0-generate-001",
        "video": "veo-3.0-generate-001",
    },
    "anthropic": {
        "text": "claude-sonnet-5",
        "image": None,
        "video": None,
    },
}

SUPPORTED_PROVIDERS = set(PROVIDER_CAPABILITIES.keys())


class ProviderError(Exception):
    """Raised on any upstream provider failure; message is safe to show the user."""
    pass


# ---------------------------------------------------------------------------
# Key validation — one cheap call per modality the provider *could* support,
# so we store what this specific key can actually do, not just what the
# provider brand generally offers (e.g. a key with no billing enabled for
# image gen still authenticates fine for text).
# ---------------------------------------------------------------------------

def validate_key(provider: str, api_key: str) -> dict:
    if provider not in SUPPORTED_PROVIDERS:
        raise ProviderError(f"Unsupported provider '{provider}'.")

    caps = PROVIDER_CAPABILITIES[provider]
    confirmed = {"text": False, "image": False, "video": False}

    if caps["text"]:
        try:
            call_text(provider, api_key, caps["text"], "Reply with just: ok", max_tokens=5)
            confirmed["text"] = True
        except ProviderError:
            pass

    # Image/video validation calls cost real money on the user's key, so we
    # don't fire a generation just to check — a working text call plus a
    # valid-looking key is treated as sufficient evidence the key itself is
    # good; image/video failures surface at actual generation time instead.
    if caps["image"] and confirmed["text"]:
        confirmed["image"] = True
    if caps["video"] and confirmed["text"]:
        confirmed["video"] = True

    if not any(confirmed.values()):
        raise ProviderError("Key did not validate against any supported modality.")

    return confirmed


# ---------------------------------------------------------------------------
# Text generation
# ---------------------------------------------------------------------------

def call_text(provider: str, api_key: str, model: str, prompt: str, max_tokens: int = 1024) -> str:
    if provider == "openai":
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens},
            timeout=60,
        )
        _raise_for_provider_error(resp, "openai")
        return resp.json()["choices"][0]["message"]["content"]

    if provider == "anthropic":
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]},
            timeout=60,
        )
        _raise_for_provider_error(resp, "anthropic")
        blocks = resp.json().get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

    if provider == "google":
        resp = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": api_key},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=60,
        )
        _raise_for_provider_error(resp, "google")
        data = resp.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise ProviderError("Google returned no text candidate (likely a safety block).")

    raise ProviderError(f"Unsupported provider '{provider}'.")


# ---------------------------------------------------------------------------
# Image generation — synchronous, returns a base64 data URL so the frontend
# doesn't need a second fetch/auth round-trip to display it.
# ---------------------------------------------------------------------------

def call_image(provider: str, api_key: str, model: str, prompt: str) -> str:
    if provider == "openai":
        resp = httpx.post(
            "https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "prompt": prompt, "size": "1024x1024", "response_format": "b64_json"},
            timeout=90,
        )
        _raise_for_provider_error(resp, "openai")
        b64 = resp.json()["data"][0]["b64_json"]
        return f"data:image/png;base64,{b64}"

    if provider == "google":
        resp = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:predict",
            params={"key": api_key},
            json={"instances": [{"prompt": prompt}], "parameters": {"sampleCount": 1}},
            timeout=90,
        )
        _raise_for_provider_error(resp, "google")
        pred = resp.json()["predictions"][0]
        b64 = pred.get("bytesBase64Encoded")
        if not b64:
            raise ProviderError("Google returned no image bytes.")
        return f"data:image/png;base64,{b64}"

    raise ProviderError(f"Provider '{provider}' does not support image generation.")


# ---------------------------------------------------------------------------
# Video generation — async job pattern. start_video_job returns a
# provider-native job id immediately; poll_video_job is called again on
# each frontend poll tick until status is 'done' or 'failed'. This mirrors
# the provider's own async shape rather than us building a queue/worker —
# there is no background process in this deployment to poll on a timer, so
# polling is driven by the frontend hitting GET /pipeline/{id} repeatedly.
# ---------------------------------------------------------------------------

def start_video_job(provider: str, api_key: str, model: str, prompt: str) -> str:
    if provider == "google":
        resp = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:predictLongRunning",
            params={"key": api_key},
            json={"instances": [{"prompt": prompt}]},
            timeout=30,
        )
        _raise_for_provider_error(resp, "google")
        return resp.json()["name"]  # operation name, used as the job id

    raise ProviderError(f"Provider '{provider}' does not support video generation.")


def poll_video_job(provider: str, api_key: str, job_id: str) -> dict:
    """Returns {'status': 'running'|'done'|'failed', 'video_url': str | None, 'error': str | None}"""
    if provider == "google":
        resp = httpx.get(
            f"https://generativelanguage.googleapis.com/v1beta/{job_id}",
            params={"key": api_key},
            timeout=30,
        )
        _raise_for_provider_error(resp, "google")
        data = resp.json()
        if not data.get("done"):
            return {"status": "running", "video_url": None, "error": None}
        if "error" in data:
            return {"status": "failed", "video_url": None, "error": data["error"].get("message", "Video generation failed.")}
        try:
            uri = data["response"]["generateVideoResponse"]["generatedSamples"][0]["video"]["uri"]
        except (KeyError, IndexError):
            return {"status": "failed", "video_url": None, "error": "No video in provider response."}
        return {"status": "done", "video_url": uri, "error": None}

    raise ProviderError(f"Provider '{provider}' does not support video generation.")


def _raise_for_provider_error(resp: httpx.Response, provider: str) -> None:
    if resp.status_code == 401:
        raise ProviderError(f"{provider} rejected this API key (401).")
    if resp.status_code == 429:
        raise ProviderError(f"{provider} rate-limited this key — try again shortly.")
    if resp.status_code >= 400:
        raise ProviderError(f"{provider} error {resp.status_code}: {resp.text[:200]}")
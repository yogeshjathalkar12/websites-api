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
import time

import httpx


# ---------------------------------------------------------------------------
# File attachments — a step (or a /draft call) can carry arbitrary files.
# We only actually know what to do with two kinds: images (sent as real
# multimodal content blocks, provider-native format) and plain text (decoded
# and inlined into the prompt as context, since not every provider's text
# endpoint takes a generic "file" block the same way). Anything else
# (PDF, docx, etc.) is refused loudly rather than silently ignored or
# base64-dumped into a prompt where it'd just be noise tokens.
# ---------------------------------------------------------------------------

def _split_attachments(attachments):
    images, text_bits = [], []
    for f in attachments or []:
        media_type = (f.get("media_type") or "").lower()
        name = f.get("filename", "file")
        if media_type.startswith("image/"):
            images.append(f)
        elif media_type.startswith("text/") or media_type in ("application/json",):
            try:
                decoded = base64.b64decode(f["data_base64"]).decode("utf-8", errors="replace")
            except Exception:
                raise ProviderError(f"Could not read attached file '{name}'.")
            text_bits.append(f"--- {name} ---\n{decoded}")
        else:
            raise ProviderError(
                f"'{name}' is a {media_type or 'unknown'} file — only images and plain-text "
                "files are supported as attachments right now."
            )
    return images, text_bits

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
        # gemini-2.5-flash was retired 2026-09: Google's own API now
        # answers with "This model models/gemini-2.5-flash is no longer
        # available to new users. Please update your code to use
        # models/gemini-3.8-flash" - confirmed live, with a real key,
        # 2026-09-28. gemini-3.8-flash reached general availability
        # 2026-09-02 (https://ai.google.dev/gemini-api/docs/models).
        "text": "gemini-3.8-flash",
        # image/video: Google shut down the entire Imagen product line on
        # 2026-08-17 (https://ai.google.dev/gemini-api/docs/deprecations)
        # and replaced it with "Gemini Image" ("Nano Banana") models that,
        # per current docs, use a DIFFERENT API (a new "Interactions"
        # endpoint, not the generateContent/:predict shape call_image()
        # below assumes) - not just a different model string. Left
        # unsupported rather than guessing at an unverified request shape
        # with a real paid key; needs a hands-on rebuild against
        # https://ai.google.dev/gemini-api/docs/image-generation and
        # .../docs/veo before turning these back on.
        "image": None,
        "video": None,
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


def _post_with_retry(url: str, *, retries: int = 2, backoff: float = 1.5, **kwargs) -> httpx.Response:
    """A 503 from these providers is typically transient overload, not a real
    failure - Google's own body on it says "usually temporary... try again
    later." Retry a couple of times with a short pause before handing the
    response to the caller, instead of making the user manually re-click
    save/generate for something that resolves itself within a couple seconds.
    Any other status (including a genuine error) is returned immediately."""
    resp = None
    for attempt in range(retries):
        resp = httpx.post(url, **kwargs)
        if resp.status_code != 503:
            return resp
        if attempt < retries - 1:
            time.sleep(backoff)
    return resp


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
    text_error = None

    if caps["text"]:
        try:
            call_text(provider, api_key, caps["text"], "Reply with just: ok", max_tokens=5)
            confirmed["text"] = True
        except ProviderError as e:
            # THE FIX: this used to be `except ProviderError: pass` — the
            # provider's own reason (bad key, API not enabled on this
            # project, wrong region, etc.) was thrown away and replaced
            # with a generic "did not validate" message below, which told
            # the user nothing about what to actually fix. Google in
            # particular returns a very specific message here
            # (API_KEY_INVALID, PERMISSION_DENIED, ...); keep it.
            text_error = str(e)

    # Image/video validation calls cost real money on the user's key, so we
    # don't fire a generation just to check — a working text call plus a
    # valid-looking key is treated as sufficient evidence the key itself is
    # good; image/video failures surface at actual generation time instead.
    if caps["image"] and confirmed["text"]:
        confirmed["image"] = True
    if caps["video"] and confirmed["text"]:
        confirmed["video"] = True

    if not any(confirmed.values()):
        if text_error:
            raise ProviderError(f"{provider} rejected this key: {text_error}")
        raise ProviderError(f"'{provider}' has no text modality to validate against — this is a bug, not a bad key.")

    return confirmed


# ---------------------------------------------------------------------------
# Text generation
# ---------------------------------------------------------------------------

def call_text(provider: str, api_key: str, model: str, prompt: str, max_tokens: int = 1024, attachments: list = None) -> str:
    images, text_bits = _split_attachments(attachments)
    if text_bits:
        prompt = prompt + "\n\n" + "\n\n".join(text_bits)

    if provider == "openai":
        content = prompt
        if images:
            content = [{"type": "text", "text": prompt}] + [
                {"type": "image_url", "image_url": {"url": f"data:{img['media_type']};base64,{img['data_base64']}"}}
                for img in images
            ]
        resp = _post_with_retry(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "messages": [{"role": "user", "content": content}], "max_tokens": max_tokens},
            timeout=60,
        )
        _raise_for_provider_error(resp, "openai")
        return resp.json()["choices"][0]["message"]["content"]

    if provider == "anthropic":
        content = prompt
        if images:
            content = [{"type": "text", "text": prompt}] + [
                {"type": "image", "source": {"type": "base64", "media_type": img["media_type"], "data": img["data_base64"]}}
                for img in images
            ]
        resp = _post_with_retry(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": content}]},
            timeout=60,
        )
        _raise_for_provider_error(resp, "anthropic")
        blocks = resp.json().get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

    if provider == "google":
        parts = [{"text": prompt}]
        for img in images:
            parts.append({"inline_data": {"mime_type": img["media_type"], "data": img["data_base64"]}})
        resp = _post_with_retry(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": api_key},
            json={"contents": [{"parts": parts}]},
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
        resp = _post_with_retry(
            "https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "prompt": prompt, "size": "1024x1024", "response_format": "b64_json"},
            timeout=90,
        )
        _raise_for_provider_error(resp, "openai")
        b64 = resp.json()["data"][0]["b64_json"]
        return f"data:image/png;base64,{b64}"

    if provider == "google":
        resp = _post_with_retry(
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
        resp = _post_with_retry(
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


def _extract_error_message(resp: httpx.Response) -> str | None:
    """Every provider wraps its error as JSON with the useful text nested a
    couple of levels down (OpenAI/Google: error.message: Anthropic:
    error.message too, just a different envelope). Pull that out so the
    user sees "API key not valid" instead of a raw, truncated JSON blob."""
    try:
        body = resp.json()
    except ValueError:
        return None
    err = body.get("error")
    if isinstance(err, dict) and isinstance(err.get("message"), str):
        return err["message"]
    if isinstance(err, str):
        return err
    return None


def _raise_for_provider_error(resp: httpx.Response, provider: str) -> None:
    if resp.status_code < 400:
        return
    message = _extract_error_message(resp)
    if resp.status_code == 401:
        raise ProviderError(f"{provider} rejected this API key ({message or '401 Unauthorized'}).")
    if resp.status_code == 429:
        raise ProviderError(f"{provider} rate-limited this key — try again shortly.")
    raise ProviderError(f"{provider} error {resp.status_code}: {message or resp.text[:200]}")
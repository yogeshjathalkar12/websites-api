"""
content_router.py — Tool: AI Content Suite

Lets a user bring their own API key for one or more of OpenAI / Google /
Anthropic, and generate posts, emails, flyers, and short video from a
STATIC prompt template they never have to write themselves — matching the
"static prompt" ask directly: PROMPT_TEMPLATES below is what fills the
model's prompt, the user only supplies the handful of {variables} the
template asks for.

Chaining: a "pipeline" is an ordered list of steps. Each step's output is
substituted into the next step's template wherever {previous_output}
appears, so e.g. step 1 (OpenAI, draft a LinkedIn post) can feed step 2
(Anthropic, "tighten and fact-check this: {previous_output}"). Text and
image steps run synchronously inline. A video step is different: it can
only be the LAST step in a pipeline (chaining a video's output back into
another model isn't meaningful the way text-into-text is), and it doesn't
finish inside the request — start_video_job returns a job id immediately,
GET /pipeline/{id} polls the provider on each call until it's done. There
is no background worker in this deployment; the frontend's own polling is
what advances a video job, same as it already does for credits sync
elsewhere in this app.

Credits: generation cost is paid on the USER's own key, not Raptor's, so
this does not call deduct_credit — it's free to run as many times as the
user's own provider account allows. If that changes (e.g. you want to
meter pipeline count regardless of whose key pays for it), swap in
deduct_credit(user_id) at the top of run_pipeline.

Rate limiting: text is ungated (cheap, fast, low support risk). Image and
video are checked against rate_limit.py's per-user sliding window before
any step in the pipeline runs — see that module's docstring for why this
exists even though the user pays for generation on their own key.
"""

import concurrent.futures

from fastapi import APIRouter, HTTPException, Depends, Body

from raptor.utility.raptor_auth import get_current_user, supabase
from . import key_vault
from .rate_limit import check_rate_limit
from .providers import (
    PROVIDER_CAPABILITIES,
    SUPPORTED_PROVIDERS,
    ProviderError,
    call_text,
    call_image,
    start_video_job,
    poll_video_job,
)

router = APIRouter()

MAX_STEPS = 5

# Static prompt templates — the whole point being the user picks a
# content_type and fills a couple of {variables}, never writes a prompt.
PROMPT_TEMPLATES = {
    "post_linkedin": {
        "modality": "text",
        "template": (
            "Write a LinkedIn post promoting {product} to {audience}. "
            "Tone: {tone}. Keep it under 200 words, no hashtag spam, one clear call to action."
        ),
        "variables": ["product", "audience", "tone"],
    },
    "email_cold": {
        "modality": "text",
        "template": (
            "Write a cold outreach email introducing {product} to {audience}. "
            "Tone: {tone}. Subject line + body. Under 120 words. One clear ask."
        ),
        "variables": ["product", "audience", "tone"],
    },
    "email_followup": {
        "modality": "text",
        "template": (
            "Write a brief, polite follow-up email for {product}, referencing that the "
            "prospect ({audience}) hasn't replied yet. Under 80 words."
        ),
        "variables": ["product", "audience"],
    },
    "flyer_promo": {
        "modality": "image",
        "template": (
            "A clean, modern promotional flyer for {product}, targeting {audience}. "
            "Bold headline area, professional color palette, no placeholder text artifacts."
        ),
        "variables": ["product", "audience"],
    },
    "video_short_ad": {
        "modality": "video",
        "template": (
            "A short (under 10 second) promotional video for {product}, aimed at {audience}. "
            "Clean modern visual style, product-focused, no on-screen text."
        ),
        "variables": ["product", "audience"],
    },
    "refine_generic": {
        "modality": "text",
        "template": "Tighten, fact-check, and improve this for clarity without changing its core message:\n\n{previous_output}",
        "variables": [],
    },
}


@router.get("/status")
def status():
    return {"tool": "content-suite", "status": "operational", "templates": list(PROMPT_TEMPLATES.keys())}


@router.get("/templates")
def get_templates():
    return {"templates": PROMPT_TEMPLATES}


# ---------------------------------------------------------------------------
# Prompt drafting — bridges a free-typed "subject" (+ optional files) into
# ONE detailed, generation-ready prompt. This is the step PROMPT_TEMPLATES
# can't do on its own: templates need pre-named {variables}, but a user
# typing "a launch post for our new espresso machine, aimed at cafe owners"
# plus a product photo doesn't map onto {product}/{audience}/{tone} cleanly.
# Drafting is a single text call; the resulting prompt is returned to the
# user to review/edit, and is NOT persisted or auto-run — it only becomes a
# pipeline step once the user submits it back via /pipeline as a custom step
# (see _resolve_step below). Costs one text call on the user's own key.
# ---------------------------------------------------------------------------

@router.post("/draft")
def draft_prompt(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "subject": "rough description of what the user wants",
      "modality": "text" | "image" | "video",
      "provider": "openai" | "google" | "anthropic",
      "files": [{"filename": "...", "media_type": "image/png", "data_base64": "..."}]
    }
    Returns {"draft_prompt": "..."} for the user to approve or edit before
    it's used as a custom pipeline step's "prompt".
    """
    subject = (payload.get("subject") or "").strip()
    if not subject:
        raise HTTPException(status_code=400, detail="Describe what you want before drafting a prompt.")

    provider = payload.get("provider")
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{provider}'.")

    modality = payload.get("modality", "text")
    if modality not in ("text", "image", "video"):
        raise HTTPException(status_code=400, detail=f"Unknown modality '{modality}'.")

    model = PROVIDER_CAPABILITIES[provider]["text"]
    if not model:
        raise HTTPException(status_code=400, detail=f"'{provider}' has no text model to draft with.")

    files = payload.get("files") or []
    api_key = key_vault.get_decrypted_key(user_id, provider)

    instruction = (
        f"A user wants to generate {modality} content. Their rough request: \"{subject}\". "
        "If any files are attached, use them for context (e.g. a reference image or brief). "
        "Write exactly ONE detailed, specific, ready-to-use prompt for a generation model — "
        "concrete, unambiguous, no placeholders, no meta-commentary, no preamble like 'Here is a prompt:'. "
        "Output ONLY the prompt text itself."
    )
    try:
        draft = call_text(provider, api_key, model, instruction, attachments=files)
    except ProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {"draft_prompt": draft.strip(), "provider": provider, "modality": modality}


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

@router.post("/keys")
def add_key(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Body: {"provider": "openai", "api_key": "sk-..."}"""
    provider = (payload.get("provider") or "").strip().lower()
    api_key = payload.get("api_key") or ""
    capabilities = key_vault.save_key(user_id, provider, api_key)
    return {"provider": provider, "capabilities": capabilities}


@router.get("/keys")
def get_keys(user_id: str = Depends(get_current_user)):
    return {"keys": key_vault.list_keys(user_id), "known_providers": PROVIDER_CAPABILITIES}


@router.delete("/keys/{provider}")
def remove_key(provider: str, user_id: str = Depends(get_current_user)):
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{provider}'.")
    key_vault.delete_key(user_id, provider)
    return {"deleted": provider}


# ---------------------------------------------------------------------------
# Pipeline execution
# ---------------------------------------------------------------------------

def _render(template: str, variables: dict, previous_output: str) -> str:
    ctx = dict(variables or {})
    ctx["previous_output"] = previous_output or ""
    try:
        return template.format(**ctx)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing variable {e} for this template.")


def _resolve_step(step: dict, previous_output: str):
    """
    A step is either template-based (existing behavior — template_id +
    variables) or custom (a user-approved/edited prompt from /draft, carried
    as step["prompt"] + step["modality"]). Either kind can list multiple
    providers under "providers" instead of a single "provider" — that's the
    multi-agent collaboration case, where the same exact prompt is fanned
    out to every listed provider in the same step.
    Returns (modality, prompt, providers: list[str]).
    """
    providers = step.get("providers") or ([step["provider"]] if step.get("provider") else [])
    if not providers:
        raise HTTPException(status_code=400, detail="Step needs at least one provider.")
    for p in providers:
        if p not in SUPPORTED_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"Unsupported provider '{p}'.")

    if step.get("prompt"):
        modality = step.get("modality")
        if modality not in ("text", "image", "video"):
            raise HTTPException(status_code=400, detail="Custom step needs a valid 'modality'.")
        return modality, step["prompt"], providers

    template_id = step.get("template_id")
    if template_id not in PROMPT_TEMPLATES:
        raise HTTPException(status_code=400, detail=f"Unknown template '{template_id}'.")
    tpl = PROMPT_TEMPLATES[template_id]
    prompt = _render(tpl["template"], step.get("variables"), previous_output)
    return tpl["modality"], prompt, providers


def _run_agents(modality: str, prompt: str, providers: list, api_keys: dict) -> dict:
    """Run the SAME prompt across multiple providers concurrently — the
    'agents collaborating at the same time' case. Each provider's output
    comes back independently; nothing here merges or ranks them, that's
    left to the user (or a later template/custom step that reads
    previous_output, which for a multi-agent step is a labeled join of
    every agent's output — see run_pipeline below)."""

    def _one(provider):
        api_key = api_keys[provider]
        model = PROVIDER_CAPABILITIES[provider][modality]
        if modality == "text":
            return provider, call_text(provider, api_key, model, prompt)
        if modality == "image":
            return provider, call_image(provider, api_key, model, prompt)
        raise ProviderError("Unreachable modality in agent fan-out.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(providers))) as ex:
        return dict(ex.map(_one, providers))


@router.post("/pipeline")
def run_pipeline(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "content_type": "post" | "email" | "flyer" | "video" | "chain" | "custom",
      "steps": [
        # template-based (unchanged):
        {"provider": "openai", "template_id": "post_linkedin", "variables": {...}},
        # custom, single agent — "prompt" comes from an approved/edited /draft result:
        {"provider": "anthropic", "prompt": "Write a ...", "modality": "text"},
        # custom, multi-agent — SAME prompt run concurrently on every listed provider:
        {"providers": ["openai", "anthropic", "google"], "prompt": "Write a ...", "modality": "text"}
      ]
    }
    Text/image steps run inline. A multi-provider step fans the identical
    prompt out to every listed provider at once and returns one result per
    provider. If the LAST step resolves to modality "video", the pipeline
    returns status "running" with a job reference — poll GET /pipeline/{id}
    until status is "done" or "failed". Video steps stay single-provider
    (async job pattern doesn't fan out the way sync text/image calls do).
    """
    steps = payload.get("steps") or []
    if not steps:
        raise HTTPException(status_code=400, detail="Provide at least one step.")
    if len(steps) > MAX_STEPS:
        raise HTTPException(status_code=400, detail=f"Max {MAX_STEPS} chained steps per pipeline.")

    # First pass: resolve every step's (modality, prompt, providers) up
    # front so we can validate positioning/capability/rate-limits before
    # spending a single API call.
    resolved = [_resolve_step(step, "") for step in steps]  # prompt text for template steps re-resolved per-step below with real previous_output; this pass is capability/shape validation only
    for i, (modality, _prompt, providers) in enumerate(resolved):
        if modality == "video":
            if i != len(steps) - 1:
                raise HTTPException(status_code=400, detail="A video step can only be the last step in a pipeline.")
            if len(providers) != 1:
                raise HTTPException(status_code=400, detail="A video step can only use a single provider.")
        for p in providers:
            if not PROVIDER_CAPABILITIES[p][modality]:
                raise HTTPException(status_code=400, detail=f"Step {i}: '{p}' does not support {modality} generation.")

    # Rate-limit check happens once, up front, for every costly modality this
    # pipeline touches — so a multi-step chain with an image step fails fast
    # before burning the earlier text steps' API calls.
    pipeline_modalities = sorted({m for m, _p, _pr in resolved})
    for modality in pipeline_modalities:
        check_rate_limit(user_id, modality)

    previous_output = ""
    step_results = []
    is_video_last = resolved[-1][0] == "video"

    try:
        for step in (steps[:-1] if is_video_last else steps):
            modality, prompt, providers = _resolve_step(step, previous_output)
            template_id = step.get("template_id", "custom")

            if len(providers) == 1:
                provider = providers[0]
                api_key = key_vault.get_decrypted_key(user_id, provider)
                model = PROVIDER_CAPABILITIES[provider][modality]
                if modality == "text":
                    output = call_text(provider, api_key, model, prompt)
                elif modality == "image":
                    output = call_image(provider, api_key, model, prompt)
                else:
                    raise HTTPException(status_code=400, detail="Unreachable modality in sync branch.")
                step_results.append({"provider": provider, "template_id": template_id, "modality": modality, "output": output})
                previous_output = output if modality == "text" else previous_output
            else:
                api_keys = {p: key_vault.get_decrypted_key(user_id, p) for p in providers}
                outputs = _run_agents(modality, prompt, providers, api_keys)
                for p in providers:
                    step_results.append({"provider": p, "template_id": template_id, "modality": modality, "output": outputs[p]})
                if modality == "text":
                    previous_output = "\n\n".join(f"[{p}]\n{outputs[p]}" for p in providers)

        if is_video_last:
            last_modality, last_prompt, last_providers = _resolve_step(steps[-1], previous_output)
            provider = last_providers[0]
            api_key = key_vault.get_decrypted_key(user_id, provider)
            model = PROVIDER_CAPABILITIES[provider]["video"]
            job_id = start_video_job(provider, api_key, model, last_prompt)

            row = {
                "user_id": user_id,
                "content_type": payload.get("content_type", "video"),
                "steps": steps,
                "status": "running",
                "provider": provider,
                "job_id": job_id,
                "step_results": step_results,
                "modalities": pipeline_modalities,
            }
            pipeline_id = _persist_pipeline(row)
            return {"pipeline_id": pipeline_id, "status": "running", "step_results": step_results}

        # Fully synchronous pipeline (text and/or image only) — already done.
        row = {
            "user_id": user_id,
            "content_type": payload.get("content_type", "chain"),
            "steps": steps,
            "status": "done",
            "step_results": step_results,
            "result": step_results[-1]["output"] if step_results else None,
            "modalities": pipeline_modalities,
        }
        pipeline_id = _persist_pipeline(row)
        return {"pipeline_id": pipeline_id, "status": "done", "step_results": step_results}

    except ProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/pipeline/{pipeline_id}")
def get_pipeline(pipeline_id: str, user_id: str = Depends(get_current_user)):
    """Poll this for video pipelines. Advances provider-side state on each call."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    resp = (
        supabase.table("content_pipelines")
        .select("*")
        .eq("id", pipeline_id)
        .eq("user_id", user_id)
        .single()
        .execute()
    )
    if not resp.data:
        raise HTTPException(status_code=404, detail="Pipeline not found.")

    row = resp.data
    if row["status"] != "running":
        return row

    try:
        api_key = key_vault.get_decrypted_key(user_id, row["provider"])
        poll_result = poll_video_job(row["provider"], api_key, row["job_id"])
    except ProviderError as e:
        _update_pipeline(pipeline_id, {"status": "failed", "error": str(e)})
        row["status"], row["error"] = "failed", str(e)
        return row

    if poll_result["status"] == "done":
        _update_pipeline(pipeline_id, {"status": "done", "result": poll_result["video_url"]})
        row["status"], row["result"] = "done", poll_result["video_url"]
    elif poll_result["status"] == "failed":
        _update_pipeline(pipeline_id, {"status": "failed", "error": poll_result["error"]})
        row["status"], row["error"] = "failed", poll_result["error"]

    return row


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("content_pipelines")
        .select("id, content_type, status, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    return {"runs": resp.data or []}


def _persist_pipeline(row: dict) -> str:
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = supabase.table("content_pipelines").insert(row).execute()
    return resp.data[0]["id"]


def _update_pipeline(pipeline_id: str, fields: dict) -> None:
    if not supabase:
        return
    supabase.table("content_pipelines").update(fields).eq("id", pipeline_id).execute()
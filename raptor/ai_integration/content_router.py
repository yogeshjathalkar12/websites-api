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


@router.post("/pipeline")
def run_pipeline(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "content_type": "post" | "email" | "flyer" | "video" | "chain",
      "steps": [
        {"provider": "openai", "template_id": "post_linkedin", "variables": {"product": "...", "audience": "...", "tone": "punchy"}},
        {"provider": "anthropic", "template_id": "refine_generic", "variables": {}}
      ]
    }
    Text/image steps run inline. If the LAST step's template is a video
    template, the pipeline returns status "running" with a job reference —
    poll GET /pipeline/{id} until status is "done" or "failed".
    """
    steps = payload.get("steps") or []
    if not steps:
        raise HTTPException(status_code=400, detail="Provide at least one step.")
    if len(steps) > MAX_STEPS:
        raise HTTPException(status_code=400, detail=f"Max {MAX_STEPS} chained steps per pipeline.")

    for i, step in enumerate(steps):
        provider = step.get("provider")
        template_id = step.get("template_id")
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"Step {i}: unsupported provider '{provider}'.")
        if template_id not in PROMPT_TEMPLATES:
            raise HTTPException(status_code=400, detail=f"Step {i}: unknown template '{template_id}'.")
        modality = PROMPT_TEMPLATES[template_id]["modality"]
        if modality == "video" and i != len(steps) - 1:
            raise HTTPException(status_code=400, detail="A video step can only be the last step in a pipeline.")
        if not PROVIDER_CAPABILITIES[provider][modality]:
            raise HTTPException(status_code=400, detail=f"Step {i}: '{provider}' does not support {modality} generation.")

    # Rate-limit check happens once, up front, for every costly modality this
    # pipeline touches — so a 5-step chain with an image step fails fast
    # before burning the earlier text steps' API calls.
    pipeline_modalities = sorted({PROMPT_TEMPLATES[s["template_id"]]["modality"] for s in steps})
    for modality in pipeline_modalities:
        check_rate_limit(user_id, modality)

    previous_output = ""
    step_results = []

    try:
        for step in steps[:-1] if PROMPT_TEMPLATES[steps[-1]["template_id"]]["modality"] == "video" else steps:
            provider = step["provider"]
            tpl = PROMPT_TEMPLATES[step["template_id"]]
            api_key = key_vault.get_decrypted_key(user_id, provider)
            prompt = _render(tpl["template"], step.get("variables"), previous_output)
            model = PROVIDER_CAPABILITIES[provider][tpl["modality"]]

            if tpl["modality"] == "text":
                output = call_text(provider, api_key, model, prompt)
            elif tpl["modality"] == "image":
                output = call_image(provider, api_key, model, prompt)
            else:
                raise HTTPException(status_code=400, detail="Unreachable modality in sync branch.")

            step_results.append({"provider": provider, "template_id": step["template_id"], "modality": tpl["modality"], "output": output})
            previous_output = output if tpl["modality"] == "text" else previous_output

        last_step = steps[-1]
        last_tpl = PROMPT_TEMPLATES[last_step["template_id"]]

        if last_tpl["modality"] == "video":
            provider = last_step["provider"]
            api_key = key_vault.get_decrypted_key(user_id, provider)
            prompt = _render(last_tpl["template"], last_step.get("variables"), previous_output)
            model = PROVIDER_CAPABILITIES[provider]["video"]
            job_id = start_video_job(provider, api_key, model, prompt)

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
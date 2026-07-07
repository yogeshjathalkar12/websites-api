"""
spintax_router.py — Tool 3: Spintax Compiler & Injection Queue

Compiles nested Spintax ("{Hi|{Good morning|Morning}}, our tool boosts
{margins|ROI}") into every unique permutation via a small recursive-descent
parser (handles nesting that plain regex can't), then batch-inserts each
generated variant into a Supabase outreach_queue table, hashed with SHA-256
so duplicates across runs are never re-queued.
"""

import hashlib
import itertools
import re
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

MAX_VARIANTS = 5000  # guardrail: nested spintax can combinatorially explode


class SpintaxParseError(Exception):
    pass


def _parse(template: str, pos: int = 0):
    """
    Recursive-descent parser. Returns (node, next_pos).
    A node is either a plain string, or a list-of-lists representing
    alternatives, each alternative itself a list of nodes to concatenate.
    """
    node_sequence = []
    buffer = ""

    while pos < len(template):
        ch = template[pos]
        if ch == "{":
            if buffer:
                node_sequence.append(buffer)
                buffer = ""
            options, pos = _parse_group(template, pos + 1)
            node_sequence.append(options)
        elif ch == "}":
            break
        else:
            buffer += ch
            pos += 1

    if buffer:
        node_sequence.append(buffer)

    return node_sequence, pos


def _parse_group(template: str, pos: int):
    """Parses the inside of a { ... } group, splitting top-level | into alternatives."""
    alternatives = []
    current_alt = []
    buffer = ""

    while pos < len(template):
        ch = template[pos]
        if ch == "{":
            if buffer:
                current_alt.append(buffer)
                buffer = ""
            sub_options, pos = _parse_group(template, pos + 1)
            current_alt.append(sub_options)
            continue
        elif ch == "|":
            if buffer:
                current_alt.append(buffer)
                buffer = ""
            alternatives.append(current_alt)
            current_alt = []
            pos += 1
            continue
        elif ch == "}":
            if buffer:
                current_alt.append(buffer)
            alternatives.append(current_alt)
            return alternatives, pos + 1
        else:
            buffer += ch
            pos += 1

    raise SpintaxParseError("Unclosed '{' in spintax template.")


def _expand(node_sequence) -> list:
    """Expands a parsed node sequence into every possible concatenated string."""
    if not node_sequence:
        return [""]

    parts_options = []
    for node in node_sequence:
        if isinstance(node, str):
            parts_options.append([node])
        else:
            # node is a list of alternatives, each alternative is itself a node_sequence
            alt_strings = []
            for alt in node:
                alt_strings.extend(_expand(alt))
            parts_options.append(alt_strings)

    combos = itertools.product(*parts_options)
    return ["".join(combo) for combo in combos]


def compile_spintax(template: str) -> list:
    if template.count("{") != template.count("}"):
        raise SpintaxParseError("Mismatched braces in spintax template.")
    node_sequence, _ = _parse(template)
    variants = _expand(node_sequence)
    return variants


@router.get("/status")
def status():
    return {"tool": "spintax-compiler", "status": "operational"}


@router.post("/compile")
def compile_and_preview(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"template": "{Hi|Hello} {name}, ..."}
    Preview-only (no queue insert, no credit spend) — lets the UI show the
    permutation count and a sample before the user commits credits to queueing.
    """
    template = payload.get("template", "")
    if not template.strip():
        raise HTTPException(status_code=400, detail="Template is empty.")

    try:
        variants = compile_spintax(template)
    except SpintaxParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(variants) > MAX_VARIANTS:
        raise HTTPException(
            status_code=400,
            detail=f"This template generates {len(variants)} variants, over the {MAX_VARIANTS} cap. Reduce nesting.",
        )

    return {
        "variant_count": len(variants),
        "sample": variants[:10],
    }


@router.post("/queue")
def compile_and_queue(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"template": "...", "campaign_id": "acme-outreach-9x2"}
    Compiles the template, hashes each variant with SHA-256 for dedup,
    and bulk-inserts into outreach_queue. 1 credit per unique variant queued.
    """
    template = payload.get("template", "")
    campaign_id = (payload.get("campaign_id") or "").strip()
    if not template.strip():
        raise HTTPException(status_code=400, detail="Template is empty.")
    if not re.match(r"^[a-zA-Z0-9_-]+$", campaign_id or ""):
        raise HTTPException(status_code=400, detail="campaign_id must be alphanumeric/dash/underscore.")

    try:
        variants = compile_spintax(template)
    except SpintaxParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(variants) > MAX_VARIANTS:
        raise HTTPException(status_code=400, detail=f"Too many variants ({len(variants)}). Cap is {MAX_VARIANTS}.")

    remaining_credits = deduct_credit(user_id, amount=len(variants))

    rows = []
    seen_hashes = set()
    for v in variants:
        h = hashlib.sha256(v.encode("utf-8")).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        rows.append({
            "user_id": user_id,
            "campaign_id": campaign_id,
            "variant_text": v,
            "variant_hash": h,
        })

    if supabase:
        try:
            # Batch insert; on_conflict on variant_hash prevents re-queueing
            # a byte-identical string that already exists for this user.
            supabase.table("outreach_queue").upsert(rows, on_conflict="user_id,variant_hash").execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Queue insert failed: {e}")

    return {
        "campaign_id": campaign_id,
        "unique_variants_queued": len(rows),
        "duplicates_skipped": len(variants) - len(rows),
        "credits_left": remaining_credits,
    }


@router.get("/queue/{campaign_id}")
def get_queue(campaign_id: str, user_id: str = Depends(get_current_user)):
    if not re.match(r"^[a-zA-Z0-9_-]+$", campaign_id):
        raise HTTPException(status_code=400, detail="Malformed campaign_id.")
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    resp = (
        supabase.table("outreach_queue")
        .select("id, variant_text, sent, created_at")
        .eq("user_id", user_id)
        .eq("campaign_id", campaign_id)
        .order("created_at", desc=False)
        .execute()
    )
    return {"campaign_id": campaign_id, "queue": resp.data or []}
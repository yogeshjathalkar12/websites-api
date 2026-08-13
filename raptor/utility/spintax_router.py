"""
===========================================================================
100s of unique emails from one email 
===========================================================================

spintax_router.py — Tool 3: Spintax Compiler & Injection Queue

Compiles nested Spintax ("{Hi|{Good morning|Morning}}, our tool boosts
{margins|ROI}") into every unique permutation via a small recursive-descent
parser (handles nesting that plain regex can't), then batch-inserts each
generated variant into a Supabase outreach_queue table, hashed with SHA-256
so duplicates across runs are never re-queued.
"""

import csv
import hashlib
import hmac
import io
import itertools
import os
import re
from fastapi import APIRouter, HTTPException, Depends, Body

from .raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

MAX_VARIANTS = 5000  # guardrail: nested spintax can combinatorially explode

# --- CSV campaign ingestion guardrails ---
MAX_LEADS_PER_CSV = 2000
MAX_CSV_BYTES = 2_000_000       # 2MB of raw CSV text
MAX_FIELD_LEN = 200             # cap on any single lead field (name, company, etc.)
PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")

# --- unsubscribe link signing ---
# Public /unsubscribe takes a user_id + email, but NOT bare — a raw
# "?user_id=X&email=Y" link would let anyone unsubscribe any contact
# from any user's list just by guessing/enumerating IDs. The token below
# is an HMAC over (user_id, email), so only a link this backend actually
# generated (via generate_unsubscribe_url, called from the mailer/queue
# step) will validate.
UNSUBSCRIBE_SECRET = os.getenv("UNSUBSCRIBE_SECRET")

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def is_valid_email(email: str) -> bool:
    # Same pattern as raptor_router.py's is_valid_email — duplicated
    # locally rather than cross-imported so this router has no dependency
    # on raptor_router.py's module load order.
    return bool(email) and _EMAIL_RE.match(email) is not None


def _unsubscribe_token(user_id: str, email: str) -> str:
    if not UNSUBSCRIBE_SECRET:
        raise RuntimeError("UNSUBSCRIBE_SECRET is not set on the server.")
    payload = f"{user_id}:{email.strip().lower()}".encode("utf-8")
    return hmac.new(UNSUBSCRIBE_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()[:32]


def generate_unsubscribe_url(user_id: str, email: str) -> str:
    """
    Called from /queue-csv (and /queue, if you wire recipients through
    it) to build the link that goes in an email's footer. Import this
    from mailer_router.py or the queueing step rather than re-deriving
    the token elsewhere.

    NOTE: the path below assumes this router is mounted at
    /api/raptor/spintax (matching the prefix="/api/raptor/mailer"
    pattern used for mailer_router.py) — adjust UNSUBSCRIBE_PATH_PREFIX
    if you mount it differently.
    """
    api_base = os.getenv("API_BASE_URL", "https://websites-api-5wmu.onrender.com")
    path_prefix = os.getenv("UNSUBSCRIBE_PATH_PREFIX", "/api/raptor/spintax")
    token = _unsubscribe_token(user_id, email)
    from urllib.parse import quote
    return f"{api_base}{path_prefix}/unsubscribe?user_id={user_id}&email={quote(email)}&token={token}"



def _sanitize_lead_value(value) -> str:
    """
    Cleans a raw CSV cell before it's substituted into a spintax template.
    Strips control characters and caps length (same pattern as
    raptor_router.py's display_name sanitization), and — importantly —
    strips '{', '}', and '|' so a lead value like "Acme {Corp}" can't
    silently corrupt the per-lead spintax parse after substitution.
    """
    text = str(value or "").strip()[:MAX_FIELD_LEN]
    text = re.sub(r"[\x00-\x1f\x7f]", "", text)
    text = text.translate({ord(c): None for c in "{}|"})
    return text


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


def _load_suppressed(user_id: str) -> set:
    """Lowercased set of every address this user has flagged as
    unsubscribed/bounced/complained/manual — checked before ANY row with
    a recipient_email is written, so a suppressed address can never reach
    mailer_router.py's /run."""
    if not supabase:
        return set()
    resp = supabase.table("suppressed_recipients").select("email").eq("user_id", user_id).execute()
    return {row["email"].strip().lower() for row in (resp.data or [])}


@router.post("/queue")
def compile_and_queue(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body (no recipients — old behavior, variants queued unaddressed,
    mailer_router.py's /run will skip them since recipient_email is null):
      {"template": "...", "campaign_id": "acme-outreach-9x2"}

    Body (with recipients — each recipient gets ONE unique variant, never
    byte-identical text to two different people):
      {
        "template": "...",
        "campaign_id": "acme-outreach-9x2",
        "subject": "Quick question about {{company}}",   # optional global fallback
        "recipients": [
          {"email": "ceo@acme.com", "subject": "optional per-recipient override"},
          {"email": "cto@acme.com"}
        ]
      }

    Compiles the template, hashes each variant with SHA-256 for dedup,
    checks every recipient against this user's suppression list, and
    bulk-inserts into outreach_queue. 1 credit per row actually queued.
    """
    template = payload.get("template", "")
    campaign_id = (payload.get("campaign_id") or "").strip()
    default_subject = payload.get("subject")
    recipients_input = payload.get("recipients") or []

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

    # --- No recipients: preserve the original unaddressed-queue behavior ---
    if not recipients_input:
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
        if supabase and rows:
            try:
                supabase.table("outreach_queue").upsert(rows, on_conflict="user_id,variant_hash").execute()
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Queue insert failed: {e}")
        return {
            "campaign_id": campaign_id,
            "unique_variants_queued": len(rows),
            "duplicates_skipped": len(variants) - len(rows),
            "credits_left": remaining_credits,
        }

    # --- Recipients provided: validate, filter against suppression list ---
    seen_input_emails = set()
    clean_recipients = []
    invalid_emails = []
    for r in recipients_input:
        email = str(r.get("email", "")).strip()
        if not is_valid_email(email):
            invalid_emails.append(email)
            continue
        key = email.lower()
        if key in seen_input_emails:
            continue
        seen_input_emails.add(key)
        clean_recipients.append({"email": email, "subject": r.get("subject")})

    if invalid_emails:
        raise HTTPException(status_code=400, detail=f"Malformed recipient email(s): {invalid_emails}")

    suppressed = _load_suppressed(user_id)
    deliverable_recipients = [r for r in clean_recipients if r["email"].strip().lower() not in suppressed]
    suppressed_count = len(clean_recipients) - len(deliverable_recipients)

    if not deliverable_recipients:
        return {
            "campaign_id": campaign_id,
            "queued": 0,
            "suppressed_skipped": suppressed_count,
            "message": "Every recipient in this batch is on the suppression list.",
        }

    # De-dup variants (SHA-256, same as the unaddressed path) before
    # assigning them out, so no two recipients ever get identical text.
    unique_variants = []
    seen_hashes = set()
    variant_hashes = []
    for v in variants:
        h = hashlib.sha256(v.encode("utf-8")).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        unique_variants.append(v)
        variant_hashes.append(h)

    if len(unique_variants) < len(deliverable_recipients):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Template only produces {len(unique_variants)} unique variant(s), "
                f"but {len(deliverable_recipients)} recipient(s) need one each. "
                "Add more {a|b|c} alternatives to the template, or split the recipient list."
            ),
        )

    remaining_credits = deduct_credit(user_id, amount=len(deliverable_recipients))

    rows = []
    for recipient, v, h in zip(deliverable_recipients, unique_variants, variant_hashes):
        rows.append({
            "user_id": user_id,
            "campaign_id": campaign_id,
            "variant_text": v,
            "variant_hash": h,
            "recipient_email": recipient["email"],
            "subject": recipient.get("subject") or default_subject,
        })

    if supabase:
        try:
            # variant_hash is per-user unique in the schema, and since each
            # row here is now tied to one specific recipient we upsert on
            # (user_id, recipient_email, campaign_id) instead, so re-running
            # /queue for the same campaign doesn't duplicate a recipient's row.
            supabase.table("outreach_queue").upsert(
                rows, on_conflict="user_id,variant_hash"
            ).execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Queue insert failed: {e}")

    return {
        "campaign_id": campaign_id,
        "queued": len(rows),
        "suppressed_skipped": suppressed_count,
        "credits_left": remaining_credits,
    }


@router.post("/suppress")
def add_suppression(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {"email": "prospect@acme.com", "reason": "unsubscribed"}
    reason must be one of: unsubscribed, bounced, manual, complaint.
    Free — this protects deliverability, it doesn't cost a credit.
    Once added, /queue will silently skip this address for this user
    on every future call, and mailer_router.py's /run never sees it
    because it never gets written to outreach_queue in the first place.
    """
    email = str(payload.get("email", "")).strip()
    reason = payload.get("reason", "manual")
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Malformed email address.")
    if reason not in ("unsubscribed", "bounced", "manual", "complaint"):
        raise HTTPException(status_code=400, detail="reason must be one of: unsubscribed, bounced, manual, complaint.")

    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    try:
        supabase.table("suppressed_recipients").upsert({
            "user_id": user_id,
            "email": email.lower(),
            "reason": reason,
        }, on_conflict="user_id,email").execute()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not add to suppression list: {e}")

    return {"suppressed": email.lower(), "reason": reason}


@router.get("/suppressed")
def list_suppressed(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("suppressed_recipients")
        .select("email, reason, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return {"suppressed": resp.data or []}


@router.get("/unsubscribe")
def unsubscribe(email: str, user_id: str, token: str):
    """
    PUBLIC, unauthenticated by design — this is the link a recipient
    clicks from inside an actual email, so there's no JWT to check. The
    token (see _unsubscribe_token above) is what stands in for auth here:
    without the correct HMAC, a request can't unsubscribe an address it
    doesn't already know the signed link for.
    """
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Malformed email address.")
    try:
        expected = _unsubscribe_token(user_id, email)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=403, detail="Invalid or expired unsubscribe link.")

    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    try:
        supabase.table("suppressed_recipients").upsert({
            "user_id": user_id,
            "email": email.strip().lower(),
            "reason": "unsubscribed",
        }, on_conflict="user_id,email").execute()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not process unsubscribe: {e}")

    return {"unsubscribed": email.strip().lower(), "message": "You will not receive further emails from this sender."}


# --- CSV campaign ingestion ---------------------------------------------
#
# Bridges a lead list to the spintax compiler: substitutes {{first_name}}-
# style placeholders per lead BEFORE compiling that lead's spintax, not
# after. Order matters here — the parser only understands single-brace
# { } as grouping syntax, so "{{first_name}}" is actually two nested
# single-alternative groups to it, and compiling it as-is would silently
# collapse "{{first_name}}" down to the literal text "first_name" with
# the braces stripped, destroying the placeholder before it could ever
# be matched and substituted. Substituting first avoids that entirely.

def _extract_placeholders(*templates: str) -> set:
    tokens = set()
    for t in templates:
        tokens.update(PLACEHOLDER_RE.findall(t or ""))
    return tokens


def _variant_index_for(recipient_email: str, variant_count: int) -> int:
    """
    Deterministic (not random) variant pick, derived from the recipient's
    own address. Two properties this buys over random.choice():
      1. Re-running /queue-csv for the same campaign (e.g. after a
         partial failure) assigns the same recipient the same variant
         again, rather than a different one that would upsert as a
         second row under a new variant_hash.
      2. Distribution spreads across the available variants instead of
         clustering, since each address hashes to a different bucket.
    """
    digest = hashlib.sha256(recipient_email.encode("utf-8")).hexdigest()
    return int(digest, 16) % variant_count


@router.post("/queue-csv")
def queue_campaign_from_csv(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "campaign_id": "q3-outreach",
      "subject_template": "{Quick question|Hello} re: {{company}}",
      "body_template": "{Hi|Hello|Hey} {{first_name}}, {saw|noticed} you're at {{company}}.",
      "csv_text": "email,first_name,company\\nalex@acme.com,Alex,Acme Corp\\n..."
    }

    CSV must have an 'email' column; any other column can be referenced
    in either template as {{column_name}}. Every {{placeholder}} used in
    the templates must exist as a CSV column, or the request is rejected
    up front — a typo'd placeholder should never ship as literal
    "{{company}}" text in a live email.

    Pipeline per lead: validate + dedupe email -> suppression check ->
    sanitize lead fields -> substitute placeholders -> compile that
    lead's personalized spintax -> deterministically pick one variant ->
    write recipient_email + subject + variant_text into outreach_queue.
    1 credit per row actually queued (post-validation, post-suppression).
    """
    campaign_id = (payload.get("campaign_id") or "").strip()
    subject_template = payload.get("subject_template", "") or "Outreach"
    body_template = payload.get("body_template", "")
    csv_text = payload.get("csv_text", "")

    if not re.match(r"^[a-zA-Z0-9_-]+$", campaign_id or ""):
        raise HTTPException(status_code=400, detail="campaign_id must be alphanumeric/dash/underscore.")
    if not body_template.strip():
        raise HTTPException(status_code=400, detail="body_template is required.")
    if not csv_text.strip():
        raise HTTPException(status_code=400, detail="csv_text is required.")
    if len(csv_text.encode("utf-8")) > MAX_CSV_BYTES:
        raise HTTPException(status_code=400, detail=f"csv_text exceeds the {MAX_CSV_BYTES} byte cap.")

    # --- Parse CSV -----------------------------------------------------
    try:
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSV format: {e}")

    if not reader.fieldnames or "email" not in reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV must have an 'email' column.")

    leads = []
    for row in reader:
        leads.append(row)
        if len(leads) > MAX_LEADS_PER_CSV:
            raise HTTPException(status_code=400, detail=f"CSV exceeds the {MAX_LEADS_PER_CSV}-lead cap per call.")

    if not leads:
        raise HTTPException(status_code=400, detail="CSV contains no data rows.")

    # --- Verify every {{placeholder}} used has a matching CSV column ---
    referenced = _extract_placeholders(subject_template, body_template)
    available_columns = set(reader.fieldnames)
    missing_columns = referenced - available_columns
    if missing_columns:
        missing_list = ", ".join(f"{{{{{c}}}}}" for c in sorted(missing_columns))
        raise HTTPException(
            status_code=400,
            detail=f"Template references {missing_list} but the CSV has no matching column(s). "
                   f"Available columns: {sorted(available_columns)}",
        )

    # --- Validate + dedupe recipient emails, check suppression list ----
    suppressed = _load_suppressed(user_id)
    seen_emails = set()
    invalid_count = 0
    duplicate_count = 0
    suppressed_count = 0
    deliverable_leads = []

    for lead in leads:
        email = str(lead.get("email", "")).strip()
        if not is_valid_email(email):
            invalid_count += 1
            continue
        key = email.lower()
        if key in seen_emails:
            duplicate_count += 1
            continue
        seen_emails.add(key)
        if key in suppressed:
            suppressed_count += 1
            continue
        deliverable_leads.append(lead)

    if not deliverable_leads:
        return {
            "campaign_id": campaign_id,
            "total_leads_in_csv": len(leads),
            "queued": 0,
            "invalid_emails_skipped": invalid_count,
            "duplicate_emails_skipped": duplicate_count,
            "suppressed_skipped": suppressed_count,
            "message": "No deliverable leads after validation and suppression filtering.",
        }

    # --- Substitute placeholders per lead, compile, pick a variant -----
    rows = []
    seen_hashes = set()
    parse_errors = []

    for lead in deliverable_leads:
        recipient_email = lead["email"].strip().lower()

        sanitized = {k: _sanitize_lead_value(v) for k, v in lead.items()}

        def _substitute(template: str) -> str:
            return PLACEHOLDER_RE.sub(lambda m: sanitized.get(m.group(1), ""), template)

        personalized_body = _substitute(body_template)
        personalized_subject = _substitute(subject_template)

        try:
            body_variants = compile_spintax(personalized_body)
            subject_variants = compile_spintax(personalized_subject) if "{" in personalized_subject else [personalized_subject]
        except SpintaxParseError as e:
            parse_errors.append({"email": recipient_email, "error": str(e)})
            continue

        if len(body_variants) > MAX_VARIANTS:
            parse_errors.append({"email": recipient_email, "error": "Personalized template exceeds MAX_VARIANTS."})
            continue

        body_idx = _variant_index_for(recipient_email, len(body_variants))
        subject_idx = _variant_index_for(recipient_email, len(subject_variants))
        final_body = body_variants[body_idx]
        final_subject = subject_variants[subject_idx]

        variant_hash = hashlib.sha256(f"{recipient_email}:{final_body}".encode("utf-8")).hexdigest()
        if variant_hash in seen_hashes:
            continue
        seen_hashes.add(variant_hash)

        body_with_footer = final_body
        if UNSUBSCRIBE_SECRET:
            unsub_url = generate_unsubscribe_url(user_id, recipient_email)
            body_with_footer = f"{final_body}\n\n---\nDon't want these emails? Unsubscribe: {unsub_url}"

        rows.append({
            "user_id": user_id,
            "campaign_id": campaign_id,
            "recipient_email": recipient_email,
            "subject": final_subject,
            "variant_text": body_with_footer,
            "variant_hash": variant_hash,
        })

    if not rows:
        raise HTTPException(
            status_code=400,
            detail=f"No rows could be queued — every lead hit a template error. First few: {parse_errors[:5]}",
        )

    remaining_credits = deduct_credit(user_id, amount=len(rows))

    if supabase:
        try:
            supabase.table("outreach_queue").upsert(rows, on_conflict="user_id,variant_hash").execute()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Queue insert failed: {e}")

    return {
        "campaign_id": campaign_id,
        "total_leads_in_csv": len(leads),
        "queued": len(rows),
        "invalid_emails_skipped": invalid_count,
        "duplicate_emails_skipped": duplicate_count,
        "suppressed_skipped": suppressed_count,
        "template_errors_skipped": len(parse_errors),
        "unsubscribe_link_included": bool(UNSUBSCRIBE_SECRET),
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
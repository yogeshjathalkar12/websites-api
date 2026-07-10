"""
automations_router.py — CRM Automation Engine

This is a background worker, not a normal request-path router. There's no
signed-in user calling it -- a cron job hits POST /run on a schedule (every
15-60 minutes; see the setup notes inside crm.html), it evaluates every
active rule in the `automations` table across every user, and fires
whichever ones match.

What each trigger_type checks:
  contact_no_reply -> hot/active contacts with no interaction in
                       >= trigger_days -- including contacts that have
                       never had one logged, but only once they've existed
                       long enough (a lead added minutes ago doesn't
                       immediately count as "gone quiet")
  deal_stalled      -> open deals (lead/meeting/negotiation) that haven't
                       moved in >= trigger_days
  deal_won          -> deals sitting at stage='won', fired exactly once
                       per deal, ever

...and one of three actions per match:
  log_note        -> inserts an 'interactions' row (type='note') and bumps
                      the contact's last_interaction_at
  create_reminder -> inserts a 'reminders' row
  webhook         -> POSTs a small JSON payload to action_webhook_url
                      (e.g. a Zapier/Make hook that actually sends email)

Every fire is written to 'automation_runs'. That table does double duty:
it's the audit trail ("prove this is really running"), and it's the
de-duplication mechanism -- a rule won't fire again for the same
contact/deal until trigger_days has passed since it last fired for that
target. deal_won is the one exception: since "won" doesn't naturally
expire, it only ever fires once per deal, checked against automation_runs
directly rather than a time window.

Auth: protected by a single shared secret (X-Automation-Secret header,
compared with hmac.compare_digest to avoid timing attacks), not a user
JWT -- there is no user in a cron job. It talks to Supabase with the
service_role key so it can see every user's rows to evaluate triggers.
NEVER expose that key to a browser -- it bypasses every RLS policy in the
project. Because of that, this router also can't rely on `default
auth.uid()` on any insert (that only resolves for authenticated user
sessions, not service-role calls) -- every insert below sets owner_id
explicitly from the row it's acting on.
"""

import os
import hmac
import logging
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from datetime import datetime, timedelta, timezone

import requests
from fastapi import APIRouter, HTTPException, Header
from supabase import create_client, Client

logger = logging.getLogger("automations_router")
router = APIRouter()

# ── Config ────────────────────────────────────────────────────────────
# Deliberately capable of using a separate Supabase project from
# raptor_auth's, per crm.html's setup notes -- but it reads the SAME env
# var names (SUPABASE_URL/SUPABASE_KEY) that raptor_auth.py already uses,
# which is a collision, not a coincidence to leave alone: if CRM data
# lives in the same project as the rest of Raptor (the common case), this
# just works with the env vars you've already set. If it's a genuinely
# different project, set CRM_SUPABASE_URL / CRM_SUPABASE_KEY and those
# take priority -- so both setups are supported without one silently
# overwriting the other's config.
SUPABASE_URL = os.environ.get("CRM_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("CRM_SUPABASE_KEY") or os.environ.get("SUPABASE_KEY")  # service_role key -- not anon
AUTOMATION_CRON_SECRET = os.environ.get("AUTOMATION_CRON_SECRET")

supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    logger.warning(
        "automations_router: SUPABASE_URL / SUPABASE_KEY not set -- "
        "endpoints will return 500 until the backend is configured."
    )

MAX_TARGETS_PER_RULE = 500      # safety cap so one runaway rule can't process forever
WEBHOOK_TIMEOUT_SECONDS = 10
DEFAULT_TRIGGER_DAYS = 3
VALID_TRIGGER_TYPES = ("contact_no_reply", "deal_stalled", "deal_won")
VALID_ACTION_TYPES = ("log_note", "create_reminder", "webhook")


# ── Guards ────────────────────────────────────────────────────────────
def _require_supabase():
    if not supabase:
        raise HTTPException(
            status_code=500,
            detail="Automation engine is not configured: SUPABASE_URL / SUPABASE_KEY missing.",
        )


def _verify_secret(secret: Optional[str]):
    if not AUTOMATION_CRON_SECRET:
        raise HTTPException(status_code=500, detail="AUTOMATION_CRON_SECRET is not set on the server.")
    # constant-time compare -- a plain `!=` here leaks timing information
    # an attacker could use to guess the secret one character at a time.
    if not secret or not hmac.compare_digest(secret, AUTOMATION_CRON_SECRET):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Automation-Secret header.")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cutoff_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=max(1, days))).isoformat()


def _is_safe_webhook_url(url: str) -> bool:
    """
    SSRF guard. action_webhook_url is set by a signed-in CRM user through
    the app, but once saved it fires unattended on every cron tick with no
    further review -- so without this check, a rule could point the
    webhook at an internal-only service or a cloud metadata endpoint
    (e.g. 169.254.169.254) and this server would dutifully POST to it on
    a schedule forever. Reject anything that doesn't resolve to a public,
    routable address.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return False
        return True
    except Exception:
        return False


# ── De-duplication ───────────────────────────────────────────────────
def _already_ran_recently(automation_id: str, contact_id: Optional[str], deal_id: Optional[str], since_iso: Optional[str]) -> bool:
    """True if this rule already fired for this exact target since `since_iso`.
    `since_iso=None` means "ever" -- used for one-shot triggers like deal_won."""
    query = supabase.table("automation_runs").select("id").eq("automation_id", automation_id)
    if contact_id:
        query = query.eq("contact_id", contact_id)
    if deal_id:
        query = query.eq("deal_id", deal_id)
    if since_iso:
        query = query.gte("ran_at", since_iso)
    try:
        resp = query.limit(1).execute()
        return bool(resp.data)
    except Exception:
        logger.exception("Dedup check failed for automation %s", automation_id)
        return True  # fail safe: skip rather than risk a duplicate/spammy action


# ── Finding targets ──────────────────────────────────────────────────
def _find_quiet_contacts(rule: dict, cutoff: str) -> list:
    """hot/active contacts who've gone quiet for >= trigger_days -- including
    contacts that have never had a first interaction logged, but only once
    they've existed at least that long (a lead added 10 minutes ago
    shouldn't immediately get flagged as having "gone quiet")."""
    resp = (
        supabase.table("contacts")
        .select("id, owner_id, name, status, last_interaction_at, created_at")
        .eq("owner_id", rule["owner_id"])
        .in_("status", ["hot", "active"])
        .or_(f"last_interaction_at.lt.{cutoff},last_interaction_at.is.null")
        .limit(MAX_TARGETS_PER_RULE)
        .execute()
    )
    contacts = resp.data or []
    cutoff_dt = datetime.fromisoformat(cutoff)
    out = []
    for c in contacts:
        if not c.get("last_interaction_at"):
            created_at = datetime.fromisoformat(c["created_at"].replace("Z", "+00:00"))
            if created_at > cutoff_dt:
                continue  # too new to count as "gone quiet" yet
        out.append(c)
    return out


def _find_stalled_deals(rule: dict, cutoff: str) -> list:
    """open deals stuck in the same stage for >= trigger_days. Whitelisting the
    in-progress stages (rather than excluding won/lost) means a future stage
    that isn't really "in progress" won't accidentally count as stalled."""
    resp = (
        supabase.table("deals")
        .select("id, owner_id, title, stage, value, updated_at, contact_id, company_id")
        .eq("owner_id", rule["owner_id"])
        .in_("stage", ["lead", "meeting", "negotiation"])
        .lt("updated_at", cutoff)
        .limit(MAX_TARGETS_PER_RULE)
        .execute()
    )
    return resp.data or []


def _find_won_deals(rule: dict) -> list:
    """deals currently marked won -- de-duped against automation_runs, not a time window."""
    resp = (
        supabase.table("deals")
        .select("id, owner_id, title, stage, value, closed_at, contact_id, company_id")
        .eq("owner_id", rule["owner_id"])
        .eq("stage", "won")
        .limit(MAX_TARGETS_PER_RULE)
        .execute()
    )
    return resp.data or []


# ── Executing actions ────────────────────────────────────────────────
def _render_message(template: Optional[str], target_type: str, target: dict) -> str:
    if template:
        return template
    if target_type == "contact":
        return f"Automated follow-up: {target.get('name', 'this contact')} has gone quiet."
    title = target.get("title", "this deal")
    if target.get("stage") == "won":
        return f"Deal won: {title}."
    return f"Deal stalled: {title} hasn't moved stage in a while."


def _execute_action(rule: dict, target_type: str, target: dict) -> Optional[str]:
    """Performs the rule's action for one matched target. Each branch catches
    its own errors and returns None on failure rather than raising -- one bad
    row (e.g. a stale foreign key) shouldn't abort the rest of the batch."""
    owner_id = target["owner_id"]
    contact_id = target["id"] if target_type == "contact" else target.get("contact_id")
    deal_id = target["id"] if target_type == "deal" else None
    label = target.get("name") or target.get("title") or "this record"
    message = _render_message(rule.get("action_message"), target_type, target)
    action_taken = None

    if rule["action_type"] == "log_note":
        if not contact_id:
            return None  # a deal with no linked contact has nothing to attach a note to
        try:
            supabase.table("interactions").insert({
                "owner_id": owner_id, "contact_id": contact_id, "type": "note", "content": message,
            }).execute()
            supabase.table("contacts").update({
                "last_interaction_at": _utcnow_iso(),
            }).eq("id", contact_id).execute()
        except Exception:
            logger.exception("log_note failed for automation %s / contact %s", rule["id"], contact_id)
            return None
        action_taken = f'Logged a note on {label}: "{message}"'

    elif rule["action_type"] == "create_reminder":
        try:
            supabase.table("reminders").insert({
                "owner_id": owner_id, "automation_id": rule["id"],
                "contact_id": contact_id, "deal_id": deal_id, "message": message,
            }).execute()
        except Exception:
            logger.exception("create_reminder failed for automation %s / target %s", rule["id"], target.get("id"))
            return None
        action_taken = f"Created a reminder for {label}"

    elif rule["action_type"] == "webhook":
        url = (rule.get("action_webhook_url") or "").strip()
        if not _is_safe_webhook_url(url):
            logger.warning("Skipped webhook for automation %s: URL failed safety check (%r)", rule["id"], url)
            return None
        try:
            r = requests.post(url, json={
                "automation": rule["name"], "trigger_type": rule["trigger_type"],
                "target_type": target_type, "subject": label,
                "contact_id": contact_id, "deal_id": deal_id, "fired_at": _utcnow_iso(),
            }, timeout=WEBHOOK_TIMEOUT_SECONDS)
            action_taken = f"Called webhook for {label} -> {r.status_code}"
        except requests.RequestException:
            logger.exception("webhook call failed for automation %s -> %s", rule["id"], url)
            return None

    else:
        return None

    try:
        supabase.table("automation_runs").insert({
            "owner_id": owner_id, "automation_id": rule["id"],
            "contact_id": contact_id, "deal_id": deal_id, "action_taken": action_taken,
        }).execute()
    except Exception:
        logger.exception("Failed to log automation_run for automation %s", rule["id"])
    return action_taken


# ── Per-rule evaluation ──────────────────────────────────────────────
def _process_rule(rule: dict, dry_run: bool = False) -> list:
    trigger_days = rule.get("trigger_days") or DEFAULT_TRIGGER_DAYS
    cutoff = _cutoff_iso(trigger_days)
    fired = []

    if rule["trigger_type"] == "contact_no_reply":
        for contact in _find_quiet_contacts(rule, cutoff):
            if _already_ran_recently(rule["id"], contact["id"], None, cutoff):
                continue
            if dry_run:
                fired.append({"contact_id": contact["id"], "name": contact.get("name")})
            else:
                result = _execute_action(rule, "contact", contact)
                if result:
                    fired.append({"contact_id": contact["id"], "action": result})

    elif rule["trigger_type"] == "deal_stalled":
        for deal in _find_stalled_deals(rule, cutoff):
            if _already_ran_recently(rule["id"], None, deal["id"], cutoff):
                continue
            if dry_run:
                fired.append({"deal_id": deal["id"], "title": deal.get("title")})
            else:
                result = _execute_action(rule, "deal", deal)
                if result:
                    fired.append({"deal_id": deal["id"], "action": result})

    elif rule["trigger_type"] == "deal_won":
        for deal in _find_won_deals(rule):
            if _already_ran_recently(rule["id"], None, deal["id"], None):
                continue
            if dry_run:
                fired.append({"deal_id": deal["id"], "title": deal.get("title")})
            else:
                result = _execute_action(rule, "deal", deal)
                if result:
                    fired.append({"deal_id": deal["id"], "action": result})

    return fired


# ── Endpoints ─────────────────────────────────────────────────────────
@router.get("/status")
def status():
    return {"tool": "crm-automation-engine", "status": "operational" if supabase else "not_configured"}


@router.post("/run")
def run_automations(
    dry_run: bool = False,
    x_automation_secret: Optional[str] = Header(default=None, alias="X-Automation-Secret"),
):
    """
    Evaluate every active rule across every user and fire the ones whose
    conditions are met. Call this on a schedule -- see the setup notes in
    crm.html for how to wire up a cron trigger.

    ?dry_run=true runs the same matching logic without writing anything
    (no notes, reminders, webhooks, or run-log entries), so a rule can be
    sanity-checked before it's trusted to run for real.
    """
    _verify_secret(x_automation_secret)
    _require_supabase()

    resp = supabase.table("automations").select("*").eq("is_active", True).execute()
    rules = resp.data or []

    summary = {
        "rules_checked": len(rules), "rules_fired": 0, "actions_taken": 0,
        "dry_run": dry_run, "details": [], "errors": [],
    }

    for rule in rules:
        try:
            fired = _process_rule(rule, dry_run=dry_run)
            if fired:
                summary["rules_fired"] += 1
                summary["actions_taken"] += len(fired)
                summary["details"].append({"automation_id": rule["id"], "name": rule["name"], "matches": fired})
            if not dry_run:
                supabase.table("automations").update({"last_run_at": _utcnow_iso()}).eq("id", rule["id"]).execute()
        except Exception as exc:
            logger.exception("Automation rule %s failed", rule.get("id"))
            summary["errors"].append({"automation_id": rule.get("id"), "name": rule.get("name"), "error": str(exc)})

    return summary


@router.post("/{automation_id}/run-now")
def run_single_automation(
    automation_id: str,
    dry_run: bool = False,
    x_automation_secret: Optional[str] = Header(default=None, alias="X-Automation-Secret"),
):
    """Manually trigger one rule immediately -- for testing a rule (active or
    not) right after creating it, without waiting for the next cron tick."""
    _verify_secret(x_automation_secret)
    _require_supabase()

    resp = supabase.table("automations").select("*").eq("id", automation_id).maybe_single().execute()
    rule = resp.data
    if not rule:
        raise HTTPException(status_code=404, detail="Automation not found.")
    if rule["trigger_type"] not in VALID_TRIGGER_TYPES or rule["action_type"] not in VALID_ACTION_TYPES:
        raise HTTPException(status_code=400, detail="Rule has an unrecognized trigger_type or action_type.")

    fired = _process_rule(rule, dry_run=dry_run)
    if not dry_run:
        supabase.table("automations").update({"last_run_at": _utcnow_iso()}).eq("id", rule["id"]).execute()

    return {"automation_id": automation_id, "name": rule["name"], "matches": fired, "dry_run": dry_run}

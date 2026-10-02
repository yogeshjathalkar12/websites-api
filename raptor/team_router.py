"""
Raptor team management: invite members, remove (offboard) them, and the
email-OTP step-up used before an owner exports bulk data.

Mounted at /api/raptor/team (see main.py). Everything here needs the Supabase
SERVICE ROLE key - inviting a user, banning one, and writing OTP rows are all
things a browser must never be able to do - so this is the one place those
actions live. Callers are authenticated with the same bearer-JWT dependency
the rest of the Raptor routers use, and every endpoint re-checks in the
database that the caller really is the organization's owner; nothing is
trusted from the request body.

The data model (organizations / org_members / audit_log / otp_codes /
step_up_grants and the offboard_member() function) is defined in the Raptor
B2B repo: db/migrations/2026-10-03_orgs_members.sql and
2026-10-03_org_rls.sql. An organization's id is its owner's auth user id.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import resend
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from raptor.utility.notifications import (
    SYSTEM_FROM_NAME,
    _notification_email_html,
)
from raptor.utility.raptor_auth import get_current_user, get_service_client

log = logging.getLogger("raptor_team")
router = APIRouter()

# The service-role client comes from raptor_auth.get_service_client(), which
# accepts the key under SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY (the name
# this app's other routers use) and refuses a key that isn't service_role.
# Resolved per request, not at import, so a missing key never stops the whole
# multi-venture hub from booting.

# Must be on Supabase's Redirect URLs allow-list (it already is: the signup
# form uses it as emailRedirectTo).
APP_URL = "https://shoonyaorigins.com/ventures/raptor/app/"

PERMISSION_KEYS = {"view_all", "create", "edit", "delete", "manage_pipeline", "manage_automations"}
OTP_PURPOSES = {"export"}
OTP_TTL = timedelta(minutes=10)
OTP_RESEND_COOLDOWN = timedelta(seconds=60)
OTP_MAX_ATTEMPTS = 5
GRANT_TTL = timedelta(minutes=10)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _client():
    sb = get_service_client()
    if not sb:
        raise HTTPException(
            status_code=500,
            detail="The server has no Supabase service-role key. Set SUPABASE_SERVICE_ROLE_KEY (or put the service_role key in SUPABASE_KEY) on Render.",
        )
    return sb


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _owner_org(user_id: str) -> str:
    """Org id if `user_id` is an active owner, otherwise 403."""
    res = (
        _client().table("org_members").select("org_id")
        .eq("user_id", user_id).eq("is_owner", True).eq("status", "active").limit(1).execute()
    )
    if not res.data:
        raise HTTPException(
            status_code=403,
            detail="Only the organization owner can do this. If you are the owner, open Raptor once so your organization is set up.",
        )
    return res.data[0]["org_id"]


def _audit(org_id: str, actor_id: str, action: str, detail: dict) -> None:
    try:
        _client().table("audit_log").insert(
            {"org_id": org_id, "actor_id": actor_id, "action": action, "detail": detail}
        ).execute()
    except Exception as err:  # the audit write must never undo the action it records
        log.error("audit_log insert failed (%s): %s", action, err)


def _send_email(to_email: str, subject: str, title: str, body: str, label: str | None = None, url: str | None = None) -> None:
    # Key: the name notifications.py uses, or RESEND_API_KEY (what the license
    # server uses). Sender: the address already proven to work on this Resend
    # account's verified domain; override with TEAM_FROM_EMAIL if needed.
    key = os.environ.get("RAPTOR_SYSTEM_RESEND_API_KEY") or os.environ.get("RESEND_API_KEY") or ""
    if not key:
        raise HTTPException(
            status_code=500,
            detail="no Resend API key is set on this server - add RESEND_API_KEY (or RAPTOR_SYSTEM_RESEND_API_KEY) in Render's Environment tab",
        )
    resend.api_key = key
    sender = os.environ.get("TEAM_FROM_EMAIL") or "onboarding@shoonyaorigins.com"
    try:
        resend.Emails.send({
            "from": f"{SYSTEM_FROM_NAME} <{sender}>",
            "to": [to_email],
            "subject": subject,
            "html": _notification_email_html(title, body, label, url),
        })
    except Exception as err:
        log.error("email to %s failed: %s", to_email, err)
        # Resend's own message (e.g. "domain is not verified") is what the
        # owner needs to see - it contains no secrets.
        raise HTTPException(status_code=502, detail=f"the email provider rejected it: {str(err)[:200]}")


def _clean_permissions(raw: dict | None) -> dict:
    return {k: True for k, v in (raw or {}).items() if k in PERMISSION_KEYS and v is True}


# ---------------------------------------------------------------- invite ---

# Everything that counts as "this login has real data of its own". Counts
# rows owned by the login in each table; the auto-seeded pipeline stages and
# system notifications are deliberately NOT here (an account that merely
# opened the CRM once still counts as empty). Used credits don't count either.
_OWNED_DATA_TABLES = [
    ("contacts", "owner_id"), ("companies", "owner_id"), ("deals", "owner_id"),
    ("interactions", "owner_id"), ("reminders", "owner_id"), ("calls", "owner_id"),
    ("campaigns", "owner_id"), ("automations", "owner_id"), ("automation_runs", "owner_id"),
    ("attachments", "owner_id"), ("custom_field_defs", "owner_id"),
    ("email_accounts", "owner_id"), ("whatsapp_accounts", "owner_id"), ("ai_content_keys", "owner_id"),
    ("pitches", "owner_id"), ("prospect_dossiers", "owner_id"), ("pipeline", "owner_id"),
    ("competitors", "owner_id"), ("pattern_events", "owner_id"), ("system_dna", "owner_id"),
    ("raptor_topups", "user_id"),
]


def _has_rows(sb, table: str, col: str, uid: str) -> bool:
    try:
        res = sb.table(table).select(col, count="exact").eq(col, uid).limit(1).execute()
        return bool(res.count) or bool(res.data)
    except Exception as err:
        text = str(err).lower()
        if "does not exist" in text or "could not find the table" in text or "pgrst205" in text or "42p01" in text:
            return False  # table not created on this database - nothing to count
        raise


def _find_auth_user(sb, email: str):
    for page in range(1, 21):
        users = sb.auth.admin.list_users(page=page, per_page=1000)
        for u in users:
            if (u.email or "").lower() == email:
                return u
        if len(users) < 1000:
            break
    return None


def _adopt_existing_account(sb, org_id: str, caller_id: str, email: str, permissions: dict, preset: str | None):
    """The invited email already has a login. If that login is a one-person
    organization with no data, no paid plan and no team of its own, turn it
    into an employee of `org_id`; otherwise refuse with a specific reason."""
    try:
        target = _find_auth_user(sb, email)
        if target is None:
            raise HTTPException(status_code=502, detail="Could not look up that account. Please try again.")
        uid = str(target.id)
        if uid == caller_id:
            raise HTTPException(status_code=400, detail="That's your own email address.")

        member = sb.table("org_members").select("org_id,is_owner,status").eq("user_id", uid).limit(1).execute()
        row = member.data[0] if member.data else None
        if row and (row["org_id"] != uid or not row["is_owner"]):
            raise HTTPException(status_code=409, detail="That person already belongs to another organization, so they can't be added to yours.")
        if row and row["status"] != "active":
            raise HTTPException(status_code=409, detail="That account has been removed from an organization and can't be added here.")

        others = sb.table("org_members").select("id").eq("org_id", uid).neq("user_id", uid).limit(1).execute()
        if others.data:
            raise HTTPException(status_code=409, detail="That person runs their own team, so they can't be added to yours.")

        plan = sb.table("raptor_users").select("plan").eq("user_id", uid).limit(1).execute()
        if plan.data and (plan.data[0].get("plan") or "Free").lower() != "free":
            raise HTTPException(status_code=409, detail="That account is on a paid plan, so it can't be converted. Ask them to use a different work email.")

        for table, col in _OWNED_DATA_TABLES:
            if _has_rows(sb, table, col, uid):
                raise HTTPException(
                    status_code=409,
                    detail="That email already has a Raptor account with its own data, so it can't be added. Ask them to use a different work email.",
                )
    except HTTPException:
        raise
    except Exception as err:
        log.error("adopt check failed for %s: %s", email, err)
        raise HTTPException(status_code=502, detail="Could not check that account. Please try again.")

    # Build the sign-in link FIRST - if that fails, nothing has been changed yet.
    try:
        link = sb.auth.admin.generate_link({"type": "magiclink", "email": email, "options": {"redirect_to": APP_URL}})
    except Exception as err:
        log.error("adopt generate_link failed: %s", err)
        raise HTTPException(status_code=502, detail="Could not create the invitation.")

    try:
        # Deleting their one-person organization cascades away its owner
        # membership row. If the insert below were to fail, they simply fall
        # back to being a solo account again (no membership row = solo), so
        # there is no state in which they lose access to their login.
        sb.table("organizations").delete().eq("id", uid).execute()
        sb.table("org_members").insert({
            "org_id": org_id, "user_id": uid, "email": email, "is_owner": False,
            "status": "invited", "preset": preset, "permissions": permissions, "invited_by": caller_id,
        }).execute()
    except Exception as err:
        log.error("adopt switch failed for %s: %s", email, err)
        raise HTTPException(status_code=500, detail="Could not add that person to your team.")

    try:
        _send_email(
            email, "You've been invited to Raptor", "You've been invited to join a Raptor team",
            "Use this link to sign in, set a new password, and join the team.", "Accept invitation", link.properties.action_link,
        )
    except HTTPException as mail_err:
        _audit(org_id, caller_id, "member_invited", {"email": email, "permissions": permissions, "email_sent": False, "converted_existing_account": True})
        raise HTTPException(status_code=502, detail=f"Member added, but the invitation email could not be sent ({mail_err.detail}). Fix that, then use Resend on their row.")

    _audit(org_id, caller_id, "member_invited", {"email": email, "permissions": permissions, "email_sent": True, "converted_existing_account": True})
    return {"ok": True, "user_id": uid, "converted": True}


class InviteBody(BaseModel):
    email: str
    permissions: dict | None = None
    preset: str | None = None


@router.post("/invite")
def invite_member(body: InviteBody, user_id: str = Depends(get_current_user)):
    org_id = _owner_org(user_id)
    sb = _client()
    email = body.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    permissions = _clean_permissions(body.permissions)

    # Already on THIS team? Say so plainly instead of a generic error.
    here = sb.table("org_members").select("status").eq("org_id", org_id).ilike("email", email).limit(1).execute()
    if here.data:
        state = here.data[0]["status"]
        msg = {
            "invited": "That person has already been invited. Use Resend on their row if the email didn't arrive.",
            "active": "That person is already on your team.",
            "removed": "That person was removed from your team. Re-adding a removed member isn't supported yet.",
        }.get(state, "That person is already part of your team.")
        raise HTTPException(status_code=409, detail=msg)

    try:
        link = sb.auth.admin.generate_link({
            "type": "invite",
            "email": email,
            "options": {"redirect_to": APP_URL, "data": {"invited_to_org": org_id}},
        })
    except Exception as err:
        # Supabase refuses to invite an address that already has a login.
        # That login may be an empty one (someone who only ever clicked
        # sign-up) - those can be converted into an employee account; a login
        # that has real data of its own can't.
        if "already" in str(err).lower() or "registered" in str(err).lower() or "exists" in str(err).lower():
            return _adopt_existing_account(sb, org_id, user_id, email, permissions, body.preset)
        log.error("generate_link failed: %s", err)
        raise HTTPException(status_code=502, detail="Could not create the invitation.")

    new_user_id = link.user.id
    try:
        sb.table("org_members").insert({
            "org_id": org_id, "user_id": new_user_id, "email": email, "is_owner": False,
            "status": "invited", "preset": body.preset, "permissions": permissions, "invited_by": user_id,
        }).execute()
    except Exception as err:
        log.error("org_members insert failed, removing orphan auth user: %s", err)
        try:
            sb.auth.admin.delete_user(new_user_id)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Could not record the invitation.")

    try:
        _send_email(
            email, "You've been invited to Raptor", "You've been invited to join a Raptor team",
            "Accept the invitation to set your password and get started.", "Accept invitation", link.properties.action_link,
        )
    except HTTPException as mail_err:
        # Keep the member row so the owner can use "Resend invite".
        _audit(org_id, user_id, "member_invited", {"email": email, "permissions": permissions, "email_sent": False})
        raise HTTPException(status_code=502, detail=f"Member added, but the invitation email could not be sent ({mail_err.detail}). Fix that, then use Resend on their row.")

    _audit(org_id, user_id, "member_invited", {"email": email, "permissions": permissions, "email_sent": True})
    return {"ok": True, "user_id": new_user_id}


class UserBody(BaseModel):
    user_id: str


@router.post("/resend-invite")
def resend_invite(body: UserBody, user_id: str = Depends(get_current_user)):
    org_id = _owner_org(user_id)
    sb = _client()
    res = (
        sb.table("org_members").select("email,status")
        .eq("org_id", org_id).eq("user_id", body.user_id).limit(1).execute()
    )
    if not res.data or res.data[0]["status"] != "invited":
        raise HTTPException(status_code=404, detail="No pending invitation for that member.")
    email = res.data[0]["email"]
    try:
        link = sb.auth.admin.generate_link({"type": "magiclink", "email": email, "options": {"redirect_to": APP_URL}})
    except Exception as err:
        log.error("resend generate_link failed: %s", err)
        raise HTTPException(status_code=502, detail="Could not create a new invitation link.")
    _send_email(
        email, "Your Raptor invitation", "Your Raptor invitation",
        "Use this link to sign in, set your password, and join the team.", "Open Raptor", link.properties.action_link,
    )
    _audit(org_id, user_id, "invite_resent", {"email": email})
    return {"ok": True}


# ---------------------------------------------------------------- remove ---

class RemoveBody(BaseModel):
    user_id: str
    reassign_to: str


@router.post("/remove")
def remove_member(body: RemoveBody, user_id: str = Depends(get_current_user)):
    """Offboarding. The database step (offboard_member) is what actually cuts
    access: it flips the membership to 'removed', and every row-level-security
    rule checks for an ACTIVE membership at query time, so the person's very
    next query returns nothing no matter how long their token has left. The
    ban and session purge after it are belt-and-braces so they also cannot
    sign in or refresh again."""
    org_id = _owner_org(user_id)
    sb = _client()
    if body.user_id == user_id:
        raise HTTPException(status_code=400, detail="The owner can't be removed.")

    try:
        result = sb.rpc("offboard_member", {
            "p_org": org_id, "p_user": body.user_id, "p_reassign_to": body.reassign_to, "p_actor": user_id,
        }).execute()
    except Exception as err:
        msg = getattr(err, "message", None) or str(err)
        raise HTTPException(status_code=400, detail=msg)

    warnings = []
    try:
        sb.auth.admin.update_user_by_id(body.user_id, {"ban_duration": "876000h"})
    except Exception as err:
        log.error("ban failed for %s: %s", body.user_id, err)
        warnings.append("could not ban the login (database access is already cut off)")
    try:
        sb.rpc("revoke_user_sessions", {"p_user": body.user_id}).execute()
    except Exception as err:
        log.error("session purge failed for %s: %s", body.user_id, err)
        warnings.append("could not purge sessions (database access is already cut off)")

    return {"ok": True, "reassigned": result.data, "warnings": warnings}


# ------------------------------------------------------------------- OTP ---

class OtpSendBody(BaseModel):
    purpose: str = "export"


class OtpVerifyBody(BaseModel):
    purpose: str = "export"
    code: str


def _otp_hash(user_id: str, purpose: str, code: str) -> str:
    secret = (
        os.environ.get("OTP_HMAC_SECRET")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_KEY")
        or ""
    ).encode()
    return hmac.new(secret, f"{user_id}:{purpose}:{code}".encode(), hashlib.sha256).hexdigest()


@router.post("/otp/send")
def otp_send(body: OtpSendBody, user_id: str = Depends(get_current_user)):
    if body.purpose not in OTP_PURPOSES:
        raise HTTPException(status_code=400, detail="Unknown purpose.")
    org_id = _owner_org(user_id)
    sb = _client()

    last = (
        sb.table("otp_codes").select("created_at").eq("user_id", user_id).eq("purpose", body.purpose)
        .order("created_at", desc=True).limit(1).execute()
    )
    if last.data and _now() - _parse_ts(last.data[0]["created_at"]) < OTP_RESEND_COOLDOWN:
        raise HTTPException(status_code=429, detail="Please wait a minute before requesting another code.")

    email = None
    me = sb.table("org_members").select("email").eq("user_id", user_id).limit(1).execute()
    if me.data:
        email = me.data[0]["email"]
    if not email:
        email = sb.auth.admin.get_user_by_id(user_id).user.email
    if not email:
        raise HTTPException(status_code=400, detail="No email address on file for this account.")

    code = f"{secrets.randbelow(10 ** 6):06d}"
    sb.table("otp_codes").delete().eq("user_id", user_id).eq("purpose", body.purpose).execute()
    sb.table("otp_codes").insert({
        "user_id": user_id, "purpose": body.purpose, "code_hash": _otp_hash(user_id, body.purpose, code),
        "expires_at": (_now() + OTP_TTL).isoformat(),
    }).execute()

    _send_email(
        email, "Your Raptor verification code", "Confirm your data export",
        f"Your verification code is <strong style=\"color:#fff;font-size:22px;letter-spacing:4px;\">{code}</strong>. "
        "It expires in 10 minutes. If you didn't request this, someone may be using your open session - sign out and change your password.",
    )
    _audit(org_id, user_id, "otp_sent", {"purpose": body.purpose})
    return {"ok": True, "expires_in": int(OTP_TTL.total_seconds())}


@router.post("/otp/verify")
def otp_verify(body: OtpVerifyBody, user_id: str = Depends(get_current_user)):
    if body.purpose not in OTP_PURPOSES:
        raise HTTPException(status_code=400, detail="Unknown purpose.")
    org_id = _owner_org(user_id)
    sb = _client()

    res = (
        sb.table("otp_codes").select("*").eq("user_id", user_id).eq("purpose", body.purpose)
        .order("created_at", desc=True).limit(1).execute()
    )
    if not res.data:
        raise HTTPException(status_code=400, detail="Request a new code first.")
    row = res.data[0]
    if _parse_ts(row["expires_at"]) < _now():
        sb.table("otp_codes").delete().eq("id", row["id"]).execute()
        raise HTTPException(status_code=400, detail="That code has expired. Request a new one.")
    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        sb.table("otp_codes").delete().eq("id", row["id"]).execute()
        raise HTTPException(status_code=429, detail="Too many wrong attempts. Request a new code.")

    submitted = _otp_hash(user_id, body.purpose, body.code.strip())
    if not hmac.compare_digest(submitted, row["code_hash"]):
        sb.table("otp_codes").update({"attempts": row["attempts"] + 1}).eq("id", row["id"]).execute()
        _audit(org_id, user_id, "otp_failed", {"purpose": body.purpose})
        raise HTTPException(status_code=400, detail="That code isn't right.")

    sb.table("otp_codes").delete().eq("id", row["id"]).execute()
    sb.table("step_up_grants").insert({
        "user_id": user_id, "purpose": body.purpose, "expires_at": (_now() + GRANT_TTL).isoformat(),
    }).execute()
    _audit(org_id, user_id, "otp_verified", {"purpose": body.purpose})
    return {"ok": True, "valid_for": int(GRANT_TTL.total_seconds())}

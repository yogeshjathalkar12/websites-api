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
    SYSTEM_FROM_EMAIL,
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
    if not resend.api_key:
        raise HTTPException(status_code=500, detail="Email sender is not configured on the server.")
    try:
        resend.Emails.send({
            "from": f"{SYSTEM_FROM_NAME} <{SYSTEM_FROM_EMAIL}>",
            "to": [to_email],
            "subject": subject,
            "html": _notification_email_html(title, body, label, url),
        })
    except Exception as err:
        log.error("email to %s failed: %s", to_email, err)
        raise HTTPException(status_code=502, detail="Could not send the email. Please try again.")


def _clean_permissions(raw: dict | None) -> dict:
    return {k: True for k, v in (raw or {}).items() if k in PERMISSION_KEYS and v is True}


# ---------------------------------------------------------------- invite ---

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

    try:
        link = sb.auth.admin.generate_link({
            "type": "invite",
            "email": email,
            "options": {"redirect_to": APP_URL, "data": {"invited_to_org": org_id}},
        })
    except Exception as err:
        # Supabase refuses to invite an address that already has an account.
        # That is exactly the "one person, one organization" rule.
        if "already" in str(err).lower() or "registered" in str(err).lower() or "exists" in str(err).lower():
            raise HTTPException(
                status_code=409,
                detail="That email already has a Raptor account, so it can't be added to another organization.",
            )
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
    except HTTPException:
        # Keep the member row so the owner can use "Resend invite".
        _audit(org_id, user_id, "member_invited", {"email": email, "permissions": permissions, "email_sent": False})
        raise HTTPException(status_code=502, detail="Member added, but the invitation email could not be sent. Use Resend invite.")

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

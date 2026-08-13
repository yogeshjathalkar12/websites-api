
"""
mailer_router.py — Tool 10: Multi-Tenant SMTP Dispatcher ("The Mailer")

Closes the loop that chronos_router.py (timing) and spintax_router.py
(content) both feed into but neither one sends: this is the piece that
actually opens an SMTP connection and fires the email, using each user's
OWN mailbox credentials rather than a shared company sender.

Architecture:
  1. Frontend collects the user's SMTP app password once, POSTs it to
     /mailer/settings. It's encrypted (mail_crypto.py) before it ever
     touches Supabase — the DB never sees plaintext.
  2. A cron job (GitHub Actions / cron-job.org) hits POST /mailer/run
     every 15-60 min, same pattern as automations_router.py's /run.
  3. /run pulls unsent rows from outreach_queue, groups by user_id,
     decrypts that user's creds in-memory only for the duration of the
     send, opens one SMTP connection per user, and sends their batch
     with randomized delays between messages (spam-velocity protection —
     same spirit as spintax's variant hashing, applied to timing).
  4. Each user has a daily send cap (mail_daily_limit) enforced here so
     one runaway campaign can't burn out someone's Gmail account (Gmail
     itself caps consumer accounts around 500/day, Workspace ~2000/day —
     default below is deliberately conservative).

NOT handled here (flagged, not silently assumed): recipient consent,
unsubscribe-link injection, and CAN-SPAM/GDPR footer requirements. Those
are legal/compliance requirements for the CALLER's outreach content, not
something this dispatcher can verify — see the compliance note at the
bottom of this file before wiring this into production sending.
"""

import os
import random
import smtplib
import ssl
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import make_msgid

from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, supabase
from mail_crypto import encrypt_secret, decrypt_secret

router = APIRouter()

DEFAULT_DAILY_LIMIT = 150          # conservative; well under Gmail's ~500/day consumer cap
MIN_DELAY_SECONDS = 45             # floor between sends for one user
MAX_DELAY_SECONDS = 120            # ceiling between sends for one user
MAX_USERS_PER_RUN = 25             # cap how many users' queues one /run call processes
MAX_SENDS_PER_USER_PER_RUN = 20    # cap per-user batch size per cron tick, so one /run call can't run for hours

KNOWN_SMTP_PRESETS = {
    "gmail": {"host": "smtp.gmail.com", "port": 587},
    "outlook": {"host": "smtp.office365.com", "port": 587},
    "yahoo": {"host": "smtp.mail.yahoo.com", "port": 587},
}


# --- credential management -------------------------------------------------

@router.get("/status")
def status():
    return {"tool": "smtp-dispatcher", "status": "operational"}


@router.post("/settings")
def save_mail_settings(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "provider": "gmail",              # or "outlook" / "yahoo" / "custom"
      "smtp_host": "smtp.gmail.com",    # required if provider == "custom"
      "smtp_port": 587,                 # required if provider == "custom"
      "from_email": "hello@shoonyaorigins.com",
      "app_password": "xxxx xxxx xxxx xxxx",
      "daily_limit": 150                # optional, defaults to DEFAULT_DAILY_LIMIT
    }
    Free — this is credential storage, not a send action. The app_password
    is encrypted before it's written and is never echoed back afterward.
    """
    provider = (payload.get("provider") or "custom").lower()
    from_email = (payload.get("from_email") or "").strip()
    app_password = payload.get("app_password") or ""
    daily_limit = int(payload.get("daily_limit", DEFAULT_DAILY_LIMIT))

    if not from_email or "@" not in from_email:
        raise HTTPException(status_code=400, detail="Valid from_email is required.")
    if not app_password:
        raise HTTPException(status_code=400, detail="app_password is required.")
    if daily_limit < 1 or daily_limit > 500:
        raise HTTPException(status_code=400, detail="daily_limit must be between 1 and 500.")

    if provider in KNOWN_SMTP_PRESETS:
        smtp_host = KNOWN_SMTP_PRESETS[provider]["host"]
        smtp_port = KNOWN_SMTP_PRESETS[provider]["port"]
    else:
        smtp_host = (payload.get("smtp_host") or "").strip()
        smtp_port = int(payload.get("smtp_port", 587))
        if not smtp_host:
            raise HTTPException(status_code=400, detail="smtp_host is required for a custom provider.")

    encrypted_password = encrypt_secret(app_password)

    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    try:
        supabase.table("user_mail_settings").upsert({
            "user_id": user_id,
            "provider": provider,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "from_email": from_email,
            "encrypted_app_password": encrypted_password,
            "daily_limit": daily_limit,
            "active": True,
        }, on_conflict="user_id").execute()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not save mail settings: {e}")

    # Never return the password, encrypted or not.
    return {
        "saved": True,
        "provider": provider,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "from_email": from_email,
        "daily_limit": daily_limit,
    }


@router.get("/settings")
def get_mail_settings(user_id: str = Depends(get_current_user)):
    """Returns configuration only — never the password, encrypted or otherwise."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("user_mail_settings")
        .select("provider, smtp_host, smtp_port, from_email, daily_limit, active, updated_at")
        .eq("user_id", user_id)
        .execute()
    )
    if not resp.data:
        return {"configured": False}
    return {"configured": True, **resp.data[0]}


@router.delete("/settings")
def delete_mail_settings(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    supabase.table("user_mail_settings").delete().eq("user_id", user_id).execute()
    return {"deleted": True}


# --- dispatch loop -----------------------------------------------------------

def _send_one(smtp_conn: smtplib.SMTP, from_email: str, to_email: str, subject: str, body: str) -> str:
    """
    Sends one message and returns the Message-ID it went out under. This
    is what makes reply-attribution possible later: threader_router.py
    can match a reply's In-Reply-To/References header against this same
    string, which is the only way to know WHICH specific outreach_queue
    row (which variant, which recipient) a given reply belongs to.
    """
    domain = from_email.split("@")[-1] if "@" in from_email else "raptor.local"
    message_id = make_msgid(domain=domain)

    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg.attach(MIMEText(body, "plain"))
    smtp_conn.sendmail(from_email, [to_email], msg.as_string())
    return message_id


def _sends_today(user_id: str) -> int:
    if not supabase:
        return 0
    # outreach_queue rows this user has already marked sent today
    resp = (
        supabase.table("outreach_queue")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .eq("sent", True)
        .gte("sent_at", _today_start_iso())
        .execute()
    )
    return resp.count or 0


def _today_start_iso() -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


@router.post("/run")
def run_dispatch(payload: dict = Body(default={})):
    """
    Cron target — no user JWT, same pattern as automations_router.py's
    /run. Protect this endpoint at the infra level (a shared secret header
    or IP allowlist checked by your cron caller), since it's meant to be
    hit unauthenticated by a scheduler, not a logged-in user.

    Body (optional): {"shared_secret": "..."}  — checked against
    MAILER_RUN_SECRET env var if you set one.
    """
    expected_secret = os.getenv("MAILER_RUN_SECRET")
    if expected_secret and payload.get("shared_secret") != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid or missing shared_secret.")

    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    # Find recipients: unsent queue rows joined conceptually against
    # outreach_queue.user_id — the target address itself has to live on
    # the queue row (see schema note below); we read it out here.
    pending = (
        supabase.table("outreach_queue")
        .select("id, user_id, variant_text, recipient_email, subject, send_after_utc")
        .eq("sent", False)
        .not_.is_("recipient_email", "null")
        .lte("send_after_utc", _now_iso())  # NULL send_after_utc never matches .lte — see fallback below
        .limit(2000)
        .execute()
    )
    rows = pending.data or []

    # Rows with no scheduled time (Chronos wasn't used for this campaign)
    # are still eligible immediately — .lte() against NULL excludes them
    # server-side, so fetch those separately rather than silently losing them.
    unscheduled = (
        supabase.table("outreach_queue")
        .select("id, user_id, variant_text, recipient_email, subject, send_after_utc")
        .eq("sent", False)
        .not_.is_("recipient_email", "null")
        .is_("send_after_utc", "null")
        .limit(2000)
        .execute()
    )
    rows.extend(unscheduled.data or [])

    if not rows:
        return {"processed_users": 0, "sent": 0, "skipped": 0, "errors": []}

    by_user = {}
    for row in rows:
        by_user.setdefault(row["user_id"], []).append(row)

    results = {"processed_users": 0, "sent": 0, "skipped": 0, "errors": []}
    user_ids = list(by_user.keys())[:MAX_USERS_PER_RUN]

    for user_id in user_ids:
        settings_resp = (
            supabase.table("user_mail_settings")
            .select("smtp_host, smtp_port, from_email, encrypted_app_password, daily_limit, active, sending_domain_id")
            .eq("user_id", user_id)
            .execute()
        )
        if not settings_resp.data or not settings_resp.data[0].get("active"):
            results["skipped"] += len(by_user[user_id])
            continue

        settings = settings_resp.data[0]

        # If a sending_domain is attached, its warmup stage — not the
        # static daily_limit — governs the real cap, and it must be
        # 'active' (DNS-verified) to send at all. No attached domain
        # means the account hasn't gone through domain setup yet; it
        # falls back to the conservative static daily_limit rather than
        # being blocked outright, so this stays usable pre-domain-warmup.
        domain_row = None
        if settings.get("sending_domain_id"):
            domain_resp = (
                supabase.table("sending_domains")
                .select("id, status, current_daily_cap")
                .eq("id", settings["sending_domain_id"])
                .execute()
            )
            domain_row = domain_resp.data[0] if domain_resp.data else None

            if not domain_row or domain_row["status"] != "active":
                results["skipped"] += len(by_user[user_id])
                results["errors"].append({
                    "user_id": user_id,
                    "error": "Sending domain is not verified/active — run /domains/{id}/verify-dns first.",
                })
                continue

        effective_cap = domain_row["current_daily_cap"] if domain_row else settings["daily_limit"]
        already_sent_today = _sends_today(user_id)
        remaining_today = max(0, effective_cap - already_sent_today)
        if remaining_today == 0:
            results["skipped"] += len(by_user[user_id])
            continue

        try:
            app_password = decrypt_secret(settings["encrypted_app_password"])
        except ValueError as e:
            results["errors"].append({"user_id": user_id, "error": str(e)})
            continue

        batch = by_user[user_id][: min(remaining_today, MAX_SENDS_PER_USER_PER_RUN)]

        try:
            context = ssl.create_default_context()
            smtp_conn = smtplib.SMTP(settings["smtp_host"], settings["smtp_port"], timeout=15)
            smtp_conn.starttls(context=context)
            smtp_conn.login(settings["from_email"], app_password)
        except Exception as e:
            results["errors"].append({"user_id": user_id, "error": f"SMTP login failed: {e}"})
            continue

        sent_this_batch = 0
        bounced_this_batch = 0

        try:
            for i, row in enumerate(batch):
                try:
                    message_id = _send_one(
                        smtp_conn,
                        settings["from_email"],
                        row["recipient_email"],
                        row.get("subject") or "",
                        row["variant_text"],
                    )
                    supabase.table("outreach_queue").update({
                        "sent": True,
                        "sent_at": _now_iso(),
                        "message_id": message_id,
                    }).eq("id", row["id"]).execute()
                    results["sent"] += 1
                    sent_this_batch += 1
                except smtplib.SMTPRecipientsRefused as e:
                    # Hard bounce (550-range) — the mail server is telling us
                    # this exact mailbox doesn't exist or won't accept mail.
                    # Suppress it now so no future campaign re-queues it.
                    results["errors"].append({"user_id": user_id, "row_id": row["id"], "error": f"Recipient refused: {e}"})
                    bounced_this_batch += 1
                    try:
                        supabase.table("suppressed_recipients").upsert({
                            "user_id": user_id,
                            "email": row["recipient_email"].strip().lower(),
                            "reason": "bounced",
                        }, on_conflict="user_id,email").execute()
                    except Exception:
                        pass
                except Exception as e:
                    results["errors"].append({"user_id": user_id, "row_id": row["id"], "error": str(e)})

                if i < len(batch) - 1:
                    time.sleep(random.uniform(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS))
        finally:
            try:
                smtp_conn.quit()
            except Exception:
                pass

        # Roll today's outcome into domain_send_stats — this is the real
        # data domains_router.py's /run-warmup reads, not a self-report.
        if domain_row and (sent_this_batch or bounced_this_batch):
            try:
                today = _today_start_iso()[:10]
                existing = (
                    supabase.table("domain_send_stats")
                    .select("id, sent_count, bounced_count")
                    .eq("domain_id", domain_row["id"])
                    .eq("stat_date", today)
                    .execute()
                )
                if existing.data:
                    row0 = existing.data[0]
                    supabase.table("domain_send_stats").update({
                        "sent_count": row0["sent_count"] + sent_this_batch,
                        "bounced_count": row0["bounced_count"] + bounced_this_batch,
                    }).eq("id", row0["id"]).execute()
                else:
                    supabase.table("domain_send_stats").insert({
                        "domain_id": domain_row["id"],
                        "stat_date": today,
                        "sent_count": sent_this_batch,
                        "bounced_count": bounced_this_batch,
                    }).execute()
            except Exception:
                pass

        results["processed_users"] += 1

    return results


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@router.get("/queue-stats")
def queue_stats(user_id: str = Depends(get_current_user)):
    """Dashboard summary: pending / sent-today / daily cap remaining."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    pending = (
        supabase.table("outreach_queue")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .eq("sent", False)
        .execute()
    )
    sent_today = _sends_today(user_id)

    settings_resp = (
        supabase.table("user_mail_settings")
        .select("daily_limit, active")
        .eq("user_id", user_id)
        .execute()
    )
    daily_limit = settings_resp.data[0]["daily_limit"] if settings_resp.data else DEFAULT_DAILY_LIMIT
    active = settings_resp.data[0]["active"] if settings_resp.data else False

    return {
        "pending": pending.count or 0,
        "sent_today": sent_today,
        "daily_limit": daily_limit,
        "remaining_today": max(0, daily_limit - sent_today),
        "mailer_active": active,
    }


# ─────────────────────────────────────────────────────────────────────────
# COMPLIANCE NOTE (read before turning /run loose on real recipients):
#
# This dispatcher sends whatever text is in outreach_queue.variant_text
# to whatever address is in recipient_email. It does not itself add an
# unsubscribe link, a physical mailing address, or verify the recipient
# opted in — those are CAN-SPAM (US) / GDPR-adjacent (EU) requirements
# that sit on the CONTENT and CONSENT side, not the delivery mechanism.
# Before pointing this at real prospects, make sure:
#   1. Your spintax templates include an unsubscribe line and physical
#      address in the footer.
#   2. You have a suppression-list check before a row is ever queued
#      (a bounced or unsubscribed address should never reach /run).
#   3. Your outreach_queue insert path (spintax_router.py's /queue)
#      checks a suppression table before writing recipient_email.
# None of that is enforced here — flagging it rather than assuming it,
# same as resolver_router.py flags its track-visit auth gap.
# ─────────────────────────────────────────────────────────────────────────
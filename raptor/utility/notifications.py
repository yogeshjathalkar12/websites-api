"""
Place at: raptor/utility/notifications.py
Import from anywhere else in the codebase as:
    from raptor.utility.notifications import send_notification

DEFAULT BEHAVIOR: every call writes to the `notifications` table only —
that's what shows up in the bell/inbox and, if display_mode is 'banner' or
'modal', as an on-top-of-everything alert. This is deliberately the default
for every event, matching "mostly in the notification section."

Email is opt-in per call via also_email=True — for the handful of events
where a user genuinely needs to know even if they're not in the app right
now (payment failed, WhatsApp account suspended, security-relevant changes).
Sent from Raptor's own transactional sender, never a user's connected BYOK
email account — those are different senders for different purposes.

    from raptor.utility.notifications import send_notification

    # Routine event — notification section only (the default):
    send_notification(
        owner_id=user_id,
        title="Campaign finished sending",
        body="Sent to 340 recipients.",
        type="success",
        display_mode="banner",
        action_label="View campaign",
        action_url="/email/campaigns",
    )

    # Genuinely needs to reach them even if they're not in the app:
    send_notification(
        owner_id=user_id,
        title="Your payment failed",
        body="We couldn't renew your Pro plan. Update your payment method to avoid losing access.",
        type="alert",
        display_mode="modal",
        action_label="Update payment method",
        action_url="/account/credits",
        also_email=True,
    )
"""
import os
from supabase import create_client
import resend

_supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# Raptor's own transactional sender — same verified domain/account as the
# Supabase Auth SMTP setup, used here via Resend's API directly instead of
# through Supabase (this isn't an auth email, it's a product notification).
resend.api_key = os.environ.get("RAPTOR_SYSTEM_RESEND_API_KEY", "")
SYSTEM_FROM_EMAIL = "raptor.support@shoonyaorigins.com"
SYSTEM_FROM_NAME = "Raptor"
LOGO_URL = "https://yogeshjathalkar12.github.io/ventures/raptor/logo.png"

VALID_TYPES = {"info", "success", "warning", "alert"}
VALID_DISPLAY_MODES = {"inbox", "banner", "modal"}


def _notification_email_html(title: str, body: str | None, action_label: str | None, action_url: str | None) -> str:
    """Same visual shell as the Supabase auth templates, so a user
    recognizes this as Raptor immediately — reused, not reinvented."""
    button = ""
    if action_label and action_url:
        full_url = action_url if action_url.startswith("http") else f"https://shoonyaorigins.com{action_url}"
        button = f"""
        <tr><td align="center" style="padding:0 40px 32px;">
          <a href="{full_url}" style="display:inline-block;background:#a855f7;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:13px 32px;border-radius:6px;">{action_label}</a>
        </td></tr>"""
    return f"""
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0f;padding:40px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
      <tr><td align="center">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#131318;border:1px solid #2a2a35;border-radius:8px;overflow:hidden;">
          <tr><td align="center" style="padding:32px 32px 16px;"><img src="{LOGO_URL}" alt="Raptor" width="120" style="display:block;"></td></tr>
          <tr><td style="padding:8px 40px 0;">
            <h1 style="color:#ffffff;font-size:20px;font-weight:600;margin:0 0 12px;text-align:center;">{title}</h1>
            {f'<p style="color:#a1a1aa;font-size:14px;line-height:1.6;margin:0 0 28px;text-align:center;">{body}</p>' if body else '<div style="height:20px;"></div>'}
          </td></tr>
          {button}
        </table>
        <p style="color:#52525b;font-size:11px;margin:24px 0 0;">Raptor · Shoonya Origins</p>
      </td></tr>
    </table>"""


def _send_system_email(to_email: str, title: str, body: str | None, action_label: str | None, action_url: str | None):
    try:
        resend.Emails.send({
            "from": f"{SYSTEM_FROM_NAME} <{SYSTEM_FROM_EMAIL}>",
            "to": [to_email],
            "subject": title,
            "html": _notification_email_html(title, body, action_label, action_url),
        })
    except Exception as err:
        # Email is supplementary — never let it break the notification
        # itself. The DB row is already written by this point regardless.
        print(f"[notifications] system email failed for {to_email}: {err}")


def send_notification(
    owner_id: str,
    title: str,
    body: str | None = None,
    type: str = "info",
    display_mode: str = "inbox",
    action_label: str | None = None,
    action_url: str | None = None,
    also_email: bool = False,
):
    if type not in VALID_TYPES:
        raise ValueError(f"type must be one of {VALID_TYPES}, got {type!r}")
    if display_mode not in VALID_DISPLAY_MODES:
        raise ValueError(f"display_mode must be one of {VALID_DISPLAY_MODES}, got {display_mode!r}")

    # Source of truth, always — this is what the bell/banner/modal read from.
    result = (
        _supabase.table("notifications")
        .insert({
            "owner_id": owner_id,
            "title": title,
            "body": body,
            "type": type,
            "display_mode": display_mode,
            "action_label": action_label,
            "action_url": action_url,
        })
        .execute()
    )

    if also_email:
        user_row = _supabase.table("raptor_users").select("email").eq("user_id", owner_id).single().execute().data
        if user_row and user_row.get("email"):
            _send_system_email(user_row["email"], title, body, action_label, action_url)

    return result


def broadcast_notification(
    title: str,
    body: str | None = None,
    type: str = "info",
    display_mode: str = "inbox",
    action_label: str | None = None,
    action_url: str | None = None,
    also_email: bool = False,
):
    """Platform-wide announcement. also_email defaults False here even more
    deliberately than send_notification — mass-emailing every user on a
    single call is a real deliverability/reputation decision, not something
    to opt into casually. Confirm you actually want that before setting it."""
    all_ids: list[str] = []
    page = 1
    while True:
        result = _supabase.auth.admin.list_users(page=page, per_page=1000)
        users = result.users if hasattr(result, "users") else result
        if not users:
            break
        all_ids.extend(u.id for u in users)
        page += 1

    rows = [
        {"owner_id": uid, "title": title, "body": body, "type": type,
         "display_mode": display_mode, "action_label": action_label, "action_url": action_url}
        for uid in all_ids
    ]
    for i in range(0, len(rows), 500):
        _supabase.table("notifications").insert(rows[i:i + 500]).execute()

    if also_email:
        emails = _supabase.table("raptor_users").select("email").execute().data
        for row in emails:
            if row.get("email"):
                _send_system_email(row["email"], title, body, action_label, action_url)

    return {"sent_to": len(all_ids)}
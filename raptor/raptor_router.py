import os
import re
from fastapi import APIRouter, Response, HTTPException, Depends
from datetime import datetime, timezone
import dns.resolver
import dns.exception
import smtplib
import socket
import base64

# Shared auth/credit module -- see raptor/utility/raptor_auth.py. Every
# tool router (this one included) draws from the same raptor_users credit
# pool and the same Supabase client, so it's defined once and imported
# everywhere instead of copy-pasted per file.
from .utility.raptor_auth import get_current_user, deduct_credit, supabase

# Initialize the router for Raptor
router = APIRouter()

API_BASE_URL = os.getenv("API_BASE_URL", "https://websites-api-5wmu.onrender.com")

# How long after a tracker is generated we treat opens as "just previewing
# it in my own mailbox" and quietly ignore them, instead of counting them
# as a real recipient open. 45s comfortably covers pasting into a compose
# window / signature editor; a real recipient opening the email almost
# always happens well after that.
TRACKER_WARMUP_SECONDS = int(os.getenv("TRACKER_WARMUP_SECONDS", "45"))

# --- SECURITY UTILS ---
def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def is_valid_campaign_id(campaign_id: str) -> bool:
    # Allow alphanumeric, dashes, and underscores only
    return re.match(r"^[a-zA-Z0-9_-]+$", campaign_id) is not None

# --- 3. RAPTOR TOOLS ---

@router.get("/status")
def get_raptor_status():
    return {"venture": "Raptor", "status": "operational", "database_connected": supabase is not None}


def _classify_smtp_code(code: int) -> str:
    """
    Turns a raw SMTP response code into one of four buckets. This is the
    core fix for "everything gets flagged as risky": we used to treat any
    non-250 code as a hard invalid, which punished perfectly good addresses
    that just hit greylisting or a slow mailbox.
    """
    if code in (250, 251):
        return "valid"
    if code in (450, 451, 452, 421):
        # Temporary failure / greylisting -- the mailbox is very likely
        # fine, the server just wants us to try again later.
        return "risky"
    if code in (550, 551, 552, 553, 554):
        # Server is actively rejecting the mailbox -- this is the one
        # bucket that actually means "this address doesn't exist".
        return "invalid"
    return "risky"


@router.get("/verify-email")
def verify_email(address: str, user_id: str = Depends(get_current_user)):
    """
    Deducts 1 credit, then pings the target mail server.
    Protected by JWT Bearer token authentication.

    Returns one of four statuses instead of a binary valid/invalid:
      - "valid"   : mailbox confirmed to exist (SMTP 250/251)
      - "invalid" : mail server explicitly rejected the mailbox (550-range)
      - "risky"   : inconclusive -- greylisted, catch-all domain, or the
                    receiving server blocked/refused our probe (very common
                    for cloud-hosted senders; NOT proof the address is bad)
      - "unknown" : DNS/network failure before we could even ask
    """
    # Security: Validate email format before processing
    if not is_valid_email(address):
        raise HTTPException(status_code=400, detail="Malformed email address detected.")

    # Deduct credit first (will abort if they have 0 credits)
    remaining_credits = deduct_credit(user_id)

    domain = address.split('@')[1]

    # --- DNS lookup ---
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=8)
        mx_record = str(records[0].exchange)
    except dns.resolver.NXDOMAIN:
        return {
            "email": address, "status": "invalid", "deliverable": False,
            "error": "Domain does not exist.", "credits_left": remaining_credits,
        }
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return {
            "email": address, "status": "unknown", "deliverable": False,
            "error": "Could not resolve mail servers for this domain.", "credits_left": remaining_credits,
        }

    # --- SMTP probe ---
    try:
        server = smtplib.SMTP(timeout=8)
        server.connect(mx_record)
        server.helo(server.local_hostname)
        server.mail('hello@shoonyaorigins.com')

        code, message = server.rcpt(str(address))
        server.quit()

        status = _classify_smtp_code(code)
        return {
            "email": address,
            "status": status,
            "deliverable": status == "valid",
            "credits_left": remaining_credits,
        }

    except (socket.timeout, TimeoutError, ConnectionRefusedError,
            smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
        # Many receiving servers (Gmail, Outlook, etc.) silently refuse or
        # rate-limit SMTP probes from cloud IPs like ours. This is NOT
        # evidence the address is bad -- it just means we couldn't confirm
        # it either way, so we report "risky" rather than "invalid".
        return {
            "email": address, "status": "risky", "deliverable": False,
            "error": "Mail server declined verification (common for major providers). "
                     "Address may still be valid.",
            "credits_left": remaining_credits,
        }
    except Exception:
        # Security: Do not leak raw Python exceptions to the client
        return {
            "email": address, "status": "unknown", "deliverable": False,
            "error": "Mail server verification failed or timed out.", "credits_left": remaining_credits,
        }


# Raw binary data for a completely transparent 1x1 image
TRANSPARENT_PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")

@router.get("/generate-tracker")
def generate_tracker(campaign_id: str, display_name: str = None, recipient_email: str = None,
                      user_id: str = Depends(get_current_user)):
    """
    Deducts 1 credit and generates the HTML tag for a tracking pixel.
    Protected by JWT Bearer token authentication.

    display_name is the human-readable name the user typed (e.g.
    "pitch-acmecorp-ceo") -- campaign_id is the sanitized, suffixed
    slug used in the actual /track/ URL.

    recipient_email is who this specific tracker is being sent to. It's
    what lets /campaign-opens later answer "which email opened this",
    since the pixel request itself carries no identity information.
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Malformed campaign ID. Use only letters, numbers, dashes, and underscores.")

    # Security: cap length and strip control characters on the free-text
    # display name before it ever reaches the database.
    if display_name:
        display_name = display_name.strip()[:120]
        display_name = re.sub(r"[\x00-\x1f\x7f]", "", display_name)
    if not display_name:
        display_name = campaign_id

    if recipient_email:
        recipient_email = recipient_email.strip()[:254]
        if not is_valid_email(recipient_email):
            raise HTTPException(status_code=400, detail="Malformed recipient email.")

    remaining_credits = deduct_credit(user_id)

    created_at = datetime.now(timezone.utc).isoformat()

    # Record ownership of this campaign_id, who it's for, and when it was
    # created. The created_at timestamp is what /track uses to filter out
    # your own compose-window preview load -- see TRACKER_WARMUP_SECONDS.
    try:
        supabase.table("raptor_campaigns").insert({
            "campaign_id": campaign_id,
            "user_id": user_id,
            "display_name": display_name,
            "recipient_email": recipient_email,
            "created_at": created_at,
        }).execute()
    except Exception:
        # If campaign_id collides (extremely unlikely given the random
        # suffix appended client-side) we still return the tracker --
        # worst case is that one campaign's opens aren't attributable.
        pass

    # We use an Environment Variable for the URL so it's not hardcoded
    tracking_url = f"{API_BASE_URL}/api/raptor/track/{campaign_id}.png"
    html_tag = f'<img src="{tracking_url}" alt="" />'

    return {
        "campaign_id": campaign_id,
        "recipient_email": recipient_email,
        "html_tag": html_tag,
        "credits_left": remaining_credits,
        "message": "Success! Copy the html_tag into your email signature. "
                    f"Opens in the first {TRACKER_WARMUP_SECONDS}s (e.g. pasting it into your "
                    "own draft) are ignored automatically and won't count.",
    }

@router.get("/track/{campaign_id}.png")
def track_email_open(campaign_id: str):
    """
    This endpoint is triggered when the recipient's mail client loads the
    pixel. It returns a blank image and logs the open in Supabase --
    UNLESS the request lands inside the "warmup window" right after the
    tracker was created, in which case we treat it as you previewing/
    pasting the tag into your own mailbox and quietly skip logging it.
    NOTE: This must remain public so email clients can trigger it without auth!
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Invalid campaign ID format.")

    if supabase:
        try:
            campaign = (
                supabase.table("raptor_campaigns")
                .select("created_at")
                .eq("campaign_id", campaign_id)
                .execute()
            )
            created_at_raw = campaign.data[0]["created_at"] if campaign.data else None
        except Exception:
            created_at_raw = None

        is_warmup = False
        if created_at_raw:
            try:
                created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
                age_seconds = (datetime.now(timezone.utc) - created_at).total_seconds()
                is_warmup = age_seconds < TRACKER_WARMUP_SECONDS
            except Exception:
                is_warmup = False

        if is_warmup:
            print(f"👀 Ignored preview-load for campaign {campaign_id} (inside warmup window)")
        else:
            print(f"🔥 EMAIL OPENED! Campaign: {campaign_id} at {datetime.now(timezone.utc)} UTC")
            supabase.table("raptor_opens").insert({"campaign_id": campaign_id}).execute()

    return Response(content=TRANSPARENT_PIXEL, media_type="image/png")


@router.get("/campaign-opens")
def get_campaign_opens(user_id: str = Depends(get_current_user)):
    """
    Returns open counts/timestamps for ONLY the calling user's own campaigns,
    including who each campaign was addressed to (recipient_email) and the
    timestamp of every real open (self-previews are already excluded at
    write-time by /track, so nothing to filter here).
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    # 1. Find which campaign_ids belong to this user, with display name + recipient
    owned = supabase.table("raptor_campaigns").select("campaign_id, display_name, recipient_email").eq("user_id", user_id).execute()
    owned_rows = owned.data or []
    campaign_ids = [row["campaign_id"] for row in owned_rows]
    meta_by_id = {
        row["campaign_id"]: {
            "display_name": row.get("display_name") or row["campaign_id"],
            "recipient_email": row.get("recipient_email"),
        }
        for row in owned_rows
    }

    if not campaign_ids:
        return {"campaigns": []}

    # 2. Fetch opens for exactly those campaign_ids, nothing else
    opens_response = (
        supabase.table("raptor_opens")
        .select("campaign_id, opened_at")
        .in_("campaign_id", campaign_ids)
        .order("opened_at", desc=True)
        .execute()
    )
    opens = opens_response.data or []

    # 3. Aggregate per campaign: total opens + every open timestamp
    summary = {}
    for row in opens:
        cid = row["campaign_id"]
        if cid not in summary:
            meta = meta_by_id.get(cid, {})
            summary[cid] = {
                "campaign_id": cid,
                "display_name": meta.get("display_name", cid),
                "recipient_email": meta.get("recipient_email"),
                "opens": 0,
                "last_open": None,
                "open_times": [],
            }
        summary[cid]["opens"] += 1
        summary[cid]["open_times"].append(row["opened_at"])
        # opens is already sorted desc by opened_at, so the first hit per
        # campaign_id is the most recent
        if summary[cid]["last_open"] is None:
            summary[cid]["last_open"] = row["opened_at"]

    # Include campaigns with zero opens too, so the dashboard can show "Pending"
    for cid in campaign_ids:
        if cid not in summary:
            meta = meta_by_id.get(cid, {})
            summary[cid] = {
                "campaign_id": cid,
                "display_name": meta.get("display_name", cid),
                "recipient_email": meta.get("recipient_email"),
                "opens": 0,
                "last_open": None,
                "open_times": [],
            }

    return {"campaigns": list(summary.values())}

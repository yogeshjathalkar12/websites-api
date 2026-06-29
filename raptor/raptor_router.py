import os
import re
import uuid
from fastapi import APIRouter, Response, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
import dns.resolver
import smtplib
import base64
from supabase import create_client, Client

# Initialize the router for Raptor
router = APIRouter()

# Security scheme for expecting "Authorization: Bearer <token>" headers
security = HTTPBearer()

# --- 1. CONNECT TO SUPABASE ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://websites-api-5wmu.onrender.com")

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- SECURITY UTILS ---
def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False

def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def is_valid_campaign_id(campaign_id: str) -> bool:
    # Allow alphanumeric, dashes, and underscores only
    return re.match(r"^[a-zA-Z0-9_-]+$", campaign_id) is not None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Validates the JWT Bearer token securely via Supabase.
    Prevents IDOR attacks where users copy URLs to access other accounts.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    
    token = credentials.credentials
    try:
        # Ask Supabase to cryptographically verify the token and return the true user
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        return user_response.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- 2. CREDIT CHECK LOGIC ---
def deduct_credit(user_id: str):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    
    # Security: Ensure user_id is a valid UUID before hitting the database
    if not is_valid_uuid(user_id):
        raise HTTPException(status_code=400, detail="Invalid User ID format. Potential security violation.")
    
    # 1. Fetch the user's current credits from the NEW raptor_users table
    # Supabase uses PostgREST which natively parameterizes queries (blocks SQL Injection)
    response = supabase.table("raptor_users").select("credits").eq("user_id", user_id).execute()
    
    if not response.data or len(response.data) == 0:
        raise HTTPException(status_code=404, detail="User account not found in database")
        
    credits = response.data[0]["credits"]
    
    # 2. Block if they are out of credits
    if credits <= 0:
        raise HTTPException(status_code=402, detail="Out of credits. Please upgrade to the Pro Plan.")
        
    # 3. Deduct 1 credit and update the database
    new_credits = credits - 1
    supabase.table("raptor_users").update({"credits": new_credits}).eq("user_id", user_id).execute()
    
    return new_credits

# --- 3. RAPTOR TOOLS ---

@router.get("/status")
def get_raptor_status():
    return {"venture": "Raptor", "status": "operational", "database_connected": supabase is not None}

@router.get("/verify-email")
def verify_email(address: str, user_id: str = Depends(get_current_user)):
    """
    Deducts 1 credit, then pings the target mail server.
    Protected by JWT Bearer token authentication.
    """
    # Security: Validate email format before processing
    if not is_valid_email(address):
        raise HTTPException(status_code=400, detail="Malformed email address detected.")

    # Deduct credit first (will abort if they have 0 credits)
    remaining_credits = deduct_credit(user_id)
    
    try:
        domain = address.split('@')[1]
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange)
        
        server = smtplib.SMTP(timeout=5)
        server.connect(mx_record)
        server.helo(server.local_hostname)
        server.mail('hello@shoonyaorigins.com') 
        
        code, message = server.rcpt(str(address))
        server.quit()
        
        if code == 250:
            return {"email": address, "status": "valid", "deliverable": True, "credits_left": remaining_credits}
        else:
            return {"email": address, "status": "invalid", "deliverable": False, "credits_left": remaining_credits}
            
    except Exception as e:
        # Security: Do not leak raw Python exceptions to the client
        return {"email": address, "status": "unknown", "deliverable": False, "error": "Mail server verification failed or timed out.", "credits_left": remaining_credits}


# Raw binary data for a completely transparent 1x1 image
TRANSPARENT_PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")

@router.get("/generate-tracker")
def generate_tracker(campaign_id: str, display_name: str = None, user_id: str = Depends(get_current_user)):
    """
    Deducts 1 credit and generates the HTML tag for a tracking pixel.
    Protected by JWT Bearer token authentication.

    display_name is the human-readable name the user typed (e.g.
    "pitch-acmecorp-ceo") -- campaign_id is the sanitized, suffixed
    slug used in the actual /track/ URL. We store both so the
    dashboard can show a readable name after a page refresh instead
    of just the slug.
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Malformed campaign ID. Use only letters, numbers, dashes, and underscores.")

    # Security: cap length and strip control characters on the free-text
    # display name before it ever reaches the database. PostgREST already
    # parameterizes this query (no SQL injection risk), this is just
    # basic input hygiene so a 10,000-character string can't be stored.
    if display_name:
        display_name = display_name.strip()[:120]
        display_name = re.sub(r"[\x00-\x1f\x7f]", "", display_name)
    if not display_name:
        display_name = campaign_id

    remaining_credits = deduct_credit(user_id)

    # Record ownership of this campaign_id so the dashboard can later
    # ask "show me opens for MY campaigns only" without raptor_opens
    # ever needing to know who owns what. This is what makes the
    # /campaign-opens endpoint below safe to expose per-user.
    # Uses the service-role key, so this bypasses RLS by design --
    # raptor_campaigns has no client-facing policies at all.
    try:
        supabase.table("raptor_campaigns").insert({
            "campaign_id": campaign_id,
            "user_id": user_id,
            "display_name": display_name
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
        "html_tag": html_tag,
        "credits_left": remaining_credits,
        "message": "Success! Copy the html_tag into your email signature."
    }

@router.get("/track/{campaign_id}.png")
def track_email_open(campaign_id: str):
    """
    This endpoint is triggered when the recipient OPENS the email.
    It returns a blank image and logs the open in Supabase.
    NOTE: This must remain public so email clients can trigger it without auth!
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Invalid campaign ID format.")

    print(f"🔥 EMAIL OPENED! Campaign: {campaign_id} at {datetime.utcnow()} UTC")
    
    # Save the open to the database so the dashboard can see it!
    if supabase:
        supabase.table("raptor_opens").insert({"campaign_id": campaign_id}).execute()
        
    return Response(content=TRANSPARENT_PIXEL, media_type="image/png")


@router.get("/campaign-opens")
def get_campaign_opens(user_id: str = Depends(get_current_user)):
    """
    Returns open counts/timestamps for ONLY the calling user's own campaigns.
    Protected by JWT Bearer token authentication.

    raptor_opens has no user_id column and no RLS policies (by design --
    it's only ever written by this backend's public /track endpoint).
    This endpoint is the one safe, server-mediated way for the dashboard
    to read open data: we first resolve which campaign_ids belong to the
    verified user via raptor_campaigns, then query raptor_opens for just
    those IDs using the service-role key (which bypasses RLS).

    The frontend must NOT query raptor_opens directly from the browser --
    there is nothing in that table to scope a query to "my campaigns only",
    so an open client-side policy would leak every user's campaign opens.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    # 1. Find which campaign_ids belong to this user, with their display names
    owned = supabase.table("raptor_campaigns").select("campaign_id, display_name").eq("user_id", user_id).execute()
    owned_rows = owned.data or []
    campaign_ids = [row["campaign_id"] for row in owned_rows]
    names_by_id = {row["campaign_id"]: (row.get("display_name") or row["campaign_id"]) for row in owned_rows}

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

    # 3. Aggregate per campaign: total opens + most recent open time
    summary = {}
    for row in opens:
        cid = row["campaign_id"]
        if cid not in summary:
            summary[cid] = {"campaign_id": cid, "display_name": names_by_id.get(cid, cid), "opens": 0, "last_open": None}
        summary[cid]["opens"] += 1
        # opens is already sorted desc by opened_at, so the first hit per
        # campaign_id is the most recent
        if summary[cid]["last_open"] is None:
            summary[cid]["last_open"] = row["opened_at"]

    # Include campaigns with zero opens too, so the dashboard can show "Pending"
    for cid in campaign_ids:
        if cid not in summary:
            summary[cid] = {"campaign_id": cid, "display_name": names_by_id.get(cid, cid), "opens": 0, "last_open": None}


    return {"campaigns": list(summary.values())}

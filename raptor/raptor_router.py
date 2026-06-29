import os
import re
import uuid
from fastapi import APIRouter, Response, HTTPException
from datetime import datetime
import dns.resolver
import smtplib
import base64
from supabase import create_client, Client

# Initialize the router for Raptor
router = APIRouter()

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
def verify_email(address: str, user_id: str):
    """
    Deducts 1 credit, then pings the target mail server.
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
        # Security: Do not leak raw Python exceptions (str(e)) to the client
        return {"email": address, "status": "unknown", "deliverable": False, "error": "Mail server verification failed or timed out.", "credits_left": remaining_credits}


# Raw binary data for a completely transparent 1x1 image
TRANSPARENT_PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")

@router.get("/generate-tracker")
def generate_tracker(campaign_id: str, user_id: str):
    """
    Deducts 1 credit and generates the HTML tag for a tracking pixel.
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Malformed campaign ID. Use only letters, numbers, dashes, and underscores.")

    remaining_credits = deduct_credit(user_id)
    
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
    """
    # Security: Validate campaign ID format
    if not is_valid_campaign_id(campaign_id):
        raise HTTPException(status_code=400, detail="Invalid campaign ID format.")

    print(f"🔥 EMAIL OPENED! Campaign: {campaign_id} at {datetime.utcnow()} UTC")
    
    # Save the open to the database so the dashboard can see it!
    if supabase:
        supabase.table("raptor_opens").insert({"campaign_id": campaign_id}).execute()
        
    return Response(content=TRANSPARENT_PIXEL, media_type="image/png")
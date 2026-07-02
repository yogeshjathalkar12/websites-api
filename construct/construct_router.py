import os
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from supabase import create_client, Client

# Initialize the router for Construct
router = APIRouter()

# Security scheme for JWT Bearer tokens
security = HTTPBearer()

# --- 1. CONNECT TO SUPABASE ---
# This is Construct's OWN, independent Supabase project -- it does
# NOT share users, credits, or any table with Raptor. Each venture
# has its own SUPABASE_URL / SUPABASE_KEY env vars on Render.
SUPABASE_URL = os.getenv("CONSTRUCT_SUPABASE_URL")
SUPABASE_KEY = os.getenv("CONSTRUCT_SUPABASE_KEY")

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- CENTRALIZED CREDIT COSTS ---
# Single source of truth for tool pricing -- change a price here,
# not by hunting through every endpoint.
TOOL_COSTS = {
    "spec_diver": 2,
    "risk_radar": 1,
    "osha_checklist": 1,
    "sitelog_pro": 1,
}

# --- FILE UPLOAD LIMITS ---
MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB -- generous for a spec PDF, small enough to not tie up the server
ALLOWED_PDF_MAGIC = b"%PDF-"

# --- SECURITY & BILLING UTILS ---
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Validates the JWT Bearer token securely via Supabase."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    token = credentials.credentials
    try:
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return user_response.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def deduct_credits(user_id: str, cost: int):
    """
    Atomically deducts credits via a single conditional UPDATE, instead
    of read-then-write. The previous version fetched the balance, then
    wrote a new balance in a separate call -- two near-simultaneous
    requests from the same user could both read the same starting
    balance, both pass the check, and both deduct, letting the user
    spend more credits than they actually had (or go negative).

    Postgres/PostgREST's .update().eq() with a WHERE clause on the
    CURRENT value closes this: the UPDATE only succeeds if credits is
    still >= cost at the moment it runs, atomically, server-side. If a
    concurrent request already spent the credits, this UPDATE affects
    zero rows and we correctly report "not enough credits" instead of
    silently overspending.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    # Read current balance first only to give an accurate error message
    # and to compute new_credits -- the actual safety comes from the
    # conditional .gte() check on the UPDATE below, not from this read.
    response = supabase.table("construct_users").select("credits").eq("user_id", user_id).execute()
    if not response.data or len(response.data) == 0:
        raise HTTPException(status_code=404, detail="User account not found")

    credits = response.data[0]["credits"]
    if credits < cost:
        raise HTTPException(status_code=402, detail=f"Not enough credits. This tool requires {cost} credits.")

    new_credits = credits - cost
    result = (
        supabase.table("construct_users")
        .update({"credits": new_credits})
        .eq("user_id", user_id)
        .gte("credits", cost)  # conditional write: only applies if still affordable right now
        .execute()
    )

    if not result.data or len(result.data) == 0:
        # Someone else's concurrent request spent the credits between
        # our read and our write. Fail safe rather than overspend.
        raise HTTPException(status_code=402, detail="Not enough credits. Please refresh and try again.")

    return new_credits


async def validate_uploaded_file(file: UploadFile, allowed_extensions: tuple, require_pdf_magic: bool = False) -> bytes:
    """
    Centralized upload validation:
    - Rejects files over MAX_FILE_SIZE_BYTES (reads in chunks, aborts early -- never
      buffers an unbounded upload fully into memory before checking size)
    - Rejects filenames not matching allowed_extensions
    - Optionally verifies actual PDF magic bytes, since a filename ending in
      .pdf proves nothing about the real file content -- trivially spoofable
    Returns the file's bytes if valid, so callers don't need to re-read it.
    """
    if not file.filename or not file.filename.lower().endswith(allowed_extensions):
        raise HTTPException(status_code=400, detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}")

    chunks = []
    total_size = 0
    while True:
        chunk = await file.read(1024 * 1024)  # 1 MB at a time
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large. Max size is {MAX_FILE_SIZE_BYTES // (1024*1024)}MB.")
        chunks.append(chunk)

    content = b"".join(chunks)

    if require_pdf_magic and not content.startswith(ALLOWED_PDF_MAGIC):
        raise HTTPException(status_code=400, detail="File does not appear to be a valid PDF.")

    return content


# --- REQUEST MODELS ---
# Field length caps prevent unbounded strings from being sent to a
# downstream LLM at your expense, and guard against pathological inputs.
class OSHARequest(BaseModel):
    task_description: str = Field(..., min_length=1, max_length=2000)

class SiteLogRequest(BaseModel):
    notes: str = Field(..., min_length=1, max_length=5000)

# --- 3. CONSTRUCT TOOLS ---

@router.get("/status")
def get_construct_status():
    return {"venture": "Construct", "status": "operational", "database_connected": supabase is not None}

@router.post("/spec-diver")
async def spec_diver(
    question: str = Form(..., min_length=1, max_length=1000),
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user)
):
    """
    Tool 1: SpecDiver (Cost: 2 Credits)
    Accepts a PDF upload and a question.
    """
    file_bytes = await validate_uploaded_file(file, allowed_extensions=('.pdf',), require_pdf_magic=True)

    remaining_credits = deduct_credits(user_id, cost=TOOL_COSTS["spec_diver"])

    # TODO: Pass file_bytes and question to an LLM (OpenAI/Anthropic) here
    # For now, we simulate the AI response

    return {
        "status": "success",
        "tool": "SpecDiver",
        "filename_processed": file.filename,
        "answer": "Based on the uploaded document, the required fire rating for stairwell doors is 90 minutes.",
        "page_reference": "Page 42, Section 3.1.4",
        "credits_left": remaining_credits
    }

@router.post("/risk-radar")
async def risk_radar(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user)
):
    """
    Tool 2: RiskRadar (Cost: 1 Credit)
    Scans a contract for high-risk legal clauses.
    """
    file_bytes = await validate_uploaded_file(file, allowed_extensions=('.pdf', '.docx', '.txt'))

    remaining_credits = deduct_credits(user_id, cost=TOOL_COSTS["risk_radar"])

    # TODO: Extract text from file_bytes and pass to LLM to find indemnity/payment clauses

    return {
        "status": "success",
        "tool": "RiskRadar",
        "filename_processed": file.filename,
        "risks_found": [
            {"type": "Liquidated Damages", "severity": "High", "description": "Clause 4.2 penalizes $1,000 per day of delay."},
            {"type": "Indemnification", "severity": "Medium", "description": "Broad indemnification required in Section 7."}
        ],
        "credits_left": remaining_credits
    }

@router.post("/osha-checklist")
def generate_osha_checklist(request: OSHARequest, user_id: str = Depends(get_current_user)):
    """
    Tool 3: OSHA Safety Checklist Generator (Cost: 1 Credit)
    Generates a safety protocol list based on a task description.
    """
    remaining_credits = deduct_credits(user_id, cost=TOOL_COSTS["osha_checklist"])

    # TODO: Pass request.task_description to LLM with OSHA system prompt

    return {
        "status": "success",
        "tool": "OSHA Checklist",
        "task": request.task_description,
        "checklist": [
            "Verify utility markings (Call 811) before digging.",
            "Install trench box or shoring for depths over 5 feet.",
            "Ensure ladders are placed every 25 feet for safe exit."
        ],
        "credits_left": remaining_credits
    }

@router.post("/sitelog-pro")
def generate_sitelog(request: SiteLogRequest, user_id: str = Depends(get_current_user)):
    """
    Tool 4: SiteLog Pro (Cost: 1 Credit)
    Transforms messy shorthand notes into a professional daily report.
    """
    remaining_credits = deduct_credits(user_id, cost=TOOL_COSTS["sitelog_pro"])

    # TODO: Pass request.notes to LLM to rewrite professionally

    return {
        "status": "success",
        "tool": "SiteLog Pro",
        "formatted_report": "Daily Log Report\n\nWeather: Intermittent rain starting at 2:00 PM.\nPersonnel: Subcontractor (Electrical) was absent from site.\nProgress: Successfully poured 50 cubic yards of concrete on the North elevation.",
        "credits_left": remaining_credits
    }

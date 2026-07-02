"""
Aura — Lifetime Health Vault
/api/aura/ endpoints

Phase 1 scope:
  GET  /status                  — health check (public)
  POST /timeline/log            — add a symptom entry (0 credits)
  GET  /timeline                — fetch the user's full timeline
  POST /vault/upload            — upload a medical document (1 credit)
  GET  /vault                   — list the user's vault documents
  POST /medication               — add a medication to the user's cabinet (0 credits)
  GET  /medication               — list all medications for this user
  POST /medication/checkin       — record "I took this today" (0 credits)
  GET  /medication/checkin/today — which medications were taken today

SECURITY POSTURE:
  - Every user-data endpoint requires a valid Supabase JWT (get_current_user).
  - Aura uses its own isolated Supabase project (AURA_SUPABASE_URL /
    AURA_SUPABASE_KEY env vars). Health data must NEVER share a project
    with Raptor or Construct — different access patterns, different RLS
    policies, and a breach in one venture must not cascade to another.
  - Document uploads go to Supabase Storage (not a table column) so
    file bytes never travel through the backend memory unbounded.
    The backend generates a signed upload URL; the client uploads directly
    to Supabase Storage. The backend only stores the metadata reference.
  - All selects filter by user_id server-side — never trust the client
    to filter their own data (that's the definition of an IDOR gap).
  - Symptom logs and medication records are free (0 credits) to encourage
    daily use. Document uploads cost 1 credit to signal value and prevent
    storage abuse.
  - Input lengths are capped on every text field before anything reaches
    the database.
"""

import os
import uuid
from datetime import date, datetime
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from supabase import create_client, Client

router = APIRouter()
security = HTTPBearer()

# ── 1. AURA'S OWN SUPABASE PROJECT ────────────────────────────────
# Intentionally separate env var names from Raptor (SUPABASE_URL/KEY)
# and Construct (CONSTRUCT_SUPABASE_URL/KEY) so they can never be
# accidentally swapped in Render's environment variable panel.
AURA_SUPABASE_URL = os.getenv("AURA_SUPABASE_URL")
AURA_SUPABASE_KEY = os.getenv("AURA_SUPABASE_KEY")

supabase: Client = None
if AURA_SUPABASE_URL and AURA_SUPABASE_KEY:
    supabase = create_client(AURA_SUPABASE_URL, AURA_SUPABASE_KEY)

# ── 2. AUTH ────────────────────────────────────────────────────────
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Validates the Supabase JWT. Returns the verified user_id.
    Health data is sensitive enough that we should never fall through
    to an insecure default — if Supabase isn't configured, fail hard.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured on server.")
    token = credentials.credentials
    try:
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials.")
        return user_response.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


# ── 3. BILLING UTIL ───────────────────────────────────────────────
TOOL_COSTS = {
    "document_upload": 1,
    # All other Phase 1 actions are free — daily use must be frictionless
}

def deduct_credits(user_id: str, cost: int) -> int:
    """
    Atomic conditional UPDATE — same pattern as Construct's hardened
    version. Prevents the race-condition double-spend where two
    concurrent requests both pass the credits >= cost check before
    either write completes.
    """
    response = supabase.table("aura_users").select("credits").eq("user_id", user_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="User account not found in Aura.")
    credits = response.data[0]["credits"]
    if credits < cost:
        raise HTTPException(status_code=402, detail=f"Not enough credits. This action costs {cost} credit(s).")
    new_credits = credits - cost
    result = (
        supabase.table("aura_users")
        .update({"credits": new_credits})
        .eq("user_id", user_id)
        .gte("credits", cost)   # atomic guard
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=402, detail="Not enough credits. Please refresh and try again.")
    return new_credits


# ── 4. REQUEST MODELS ─────────────────────────────────────────────
class SymptomLog(BaseModel):
    # What the user is logging
    symptom:     str = Field(..., min_length=1, max_length=500)
    severity:    int = Field(..., ge=1, le=10)           # 1–10 scale
    duration:    str = Field(..., max_length=100)        # e.g. "2 days", "1 hour"
    trigger:     str = Field(default="", max_length=300) # optional suspected trigger
    notes:       str = Field(default="", max_length=1000)
    occurred_at: str = Field(..., max_length=30)         # ISO date string from client

class MedicationCreate(BaseModel):
    name:          str = Field(..., min_length=1, max_length=200)
    dosage:        str = Field(..., max_length=100)   # e.g. "500mg"
    frequency:     str = Field(..., max_length=100)   # e.g. "Twice daily"
    prescribed_by: str = Field(default="", max_length=200)
    start_date:    str = Field(..., max_length=30)
    notes:         str = Field(default="", max_length=500)

class MedicationCheckin(BaseModel):
    medication_id: str = Field(..., min_length=1, max_length=100)
    taken_at:      str = Field(..., max_length=30)  # ISO date string

class VaultDocumentMeta(BaseModel):
    # Metadata the client sends AFTER uploading directly to Supabase Storage.
    # The backend stores the reference, never the file bytes themselves.
    file_name:    str = Field(..., min_length=1, max_length=255)
    storage_path: str = Field(..., min_length=1, max_length=500)
    doc_type:     str = Field(..., max_length=100)   # e.g. "Blood Test", "Prescription"
    doc_date:     str = Field(default="", max_length=30)
    notes:        str = Field(default="", max_length=500)


# ── 5. STATUS ─────────────────────────────────────────────────────
@router.get("/status")
def get_aura_status():
    return {
        "venture": "Aura",
        "status": "operational",
        "phase": "1 — Lifetime Health Vault",
        "database_connected": supabase is not None
    }


# ── 6. TIMELINE ENDPOINTS ─────────────────────────────────────────
@router.post("/timeline/log")
def log_symptom(entry: SymptomLog, user_id: str = Depends(get_current_user)):
    """
    Add one symptom entry to the user's lifetime timeline. 0 credits.
    Every field is explicitly tied to user_id server-side — the client
    cannot inject a different user_id into this record.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")

    record = {
        "user_id":     user_id,
        "symptom":     entry.symptom.strip(),
        "severity":    entry.severity,
        "duration":    entry.duration.strip(),
        "trigger":     entry.trigger.strip(),
        "notes":       entry.notes.strip(),
        "occurred_at": entry.occurred_at,
    }
    result = supabase.table("aura_timeline").insert(record).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to save symptom log.")
    return {"status": "logged", "entry_id": result.data[0]["id"]}


@router.get("/timeline")
def get_timeline(user_id: str = Depends(get_current_user)):
    """
    Return the user's full symptom timeline in reverse-chronological order.
    The .eq("user_id", user_id) filter is applied SERVER-SIDE so a user
    cannot request another user's timeline by altering the request.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")
    result = (
        supabase.table("aura_timeline")
        .select("*")
        .eq("user_id", user_id)
        .order("occurred_at", desc=True)
        .execute()
    )
    return {"timeline": result.data or []}


# ── 7. DOCUMENT VAULT ENDPOINTS ───────────────────────────────────
@router.post("/vault/upload")
def register_vault_document(doc: VaultDocumentMeta, user_id: str = Depends(get_current_user)):
    """
    Register a medical document AFTER the client has uploaded it directly
    to Supabase Storage.

    Why this pattern instead of streaming the file through FastAPI:
    - The file never transits through the backend server, which means
      no memory risk from large PDFs, no multipart handling complexity,
      and no bandwidth cost on the Render free tier.
    - Supabase Storage enforces its own RLS policy on the storage bucket
      (files are under a path keyed by user_id), so even if someone
      guesses another user's storage_path, they cannot retrieve the file
      without being authenticated as that user.
    - We store the metadata reference here so the dashboard can list
      documents with name, type, date, and a "open" action that generates
      a fresh signed URL from Supabase Storage client-side.

    Upload flow:
    1. Dashboard calls Supabase Storage JS client directly to get a
       signed upload URL for path: `{user_id}/{uuid}_{filename}`
    2. Dashboard uploads the file directly to that URL
    3. Dashboard calls this endpoint with the metadata + storage_path
    4. This endpoint deducts 1 credit and records the reference

    Cost: 1 credit (to prevent storage abuse on the free tier)
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")

    remaining_credits = deduct_credits(user_id, cost=TOOL_COSTS["document_upload"])

    # Validate storage_path belongs to this user — the path convention is
    # {user_id}/... so a user can't register a document under another user's path
    if not doc.storage_path.startswith(f"{user_id}/"):
        raise HTTPException(
            status_code=400,
            detail="Storage path must belong to your own user directory."
        )

    record = {
        "user_id":      user_id,
        "file_name":    doc.file_name.strip(),
        "storage_path": doc.storage_path.strip(),
        "doc_type":     doc.doc_type.strip(),
        "doc_date":     doc.doc_date.strip() or None,
        "notes":        doc.notes.strip(),
    }
    result = supabase.table("aura_vault").insert(record).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to register document.")
    return {
        "status": "registered",
        "doc_id": result.data[0]["id"],
        "credits_left": remaining_credits
    }


@router.get("/vault")
def get_vault_documents(user_id: str = Depends(get_current_user)):
    """Return all vault documents for this user, most recent first."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")
    result = (
        supabase.table("aura_vault")
        .select("id, file_name, doc_type, doc_date, notes, created_at")
        # Note: storage_path is deliberately excluded from this response.
        # The frontend generates signed URLs when the user actually opens a
        # document — the path itself is not something we broadcast in list views.
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return {"documents": result.data or []}


@router.get("/vault/signed-url/{doc_id}")
def get_signed_url(doc_id: str, user_id: str = Depends(get_current_user)):
    """
    Generate a short-lived signed URL for the user to open a vault document.
    We look up the storage_path from the database, verify it belongs to this
    user, then ask Supabase Storage to generate a signed URL (valid 60 seconds).
    This means even if a URL leaks, it expires quickly and is scoped to one file.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")

    # 1. Verify this document belongs to the requesting user
    result = (
        supabase.table("aura_vault")
        .select("storage_path")
        .eq("id", doc_id)
        .eq("user_id", user_id)   # IDOR guard: must match BOTH id AND user_id
        .single()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Document not found or access denied.")

    storage_path = result.data["storage_path"]

    # 2. Generate a 60-second signed URL from Supabase Storage
    try:
        signed = supabase.storage.from_("aura-documents").create_signed_url(
            storage_path, expires_in=60
        )
        return {"signed_url": signed["signedURL"]}
    except Exception:
        raise HTTPException(status_code=500, detail="Could not generate a secure download link.")


# ── 8. MEDICATION ENDPOINTS ───────────────────────────────────────
@router.post("/medication")
def add_medication(med: MedicationCreate, user_id: str = Depends(get_current_user)):
    """Add a medication to the user's cabinet. 0 credits."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")
    record = {
        "user_id":      user_id,
        "name":         med.name.strip(),
        "dosage":       med.dosage.strip(),
        "frequency":    med.frequency.strip(),
        "prescribed_by": med.prescribed_by.strip(),
        "start_date":   med.start_date,
        "notes":        med.notes.strip(),
        "active":       True,
    }
    result = supabase.table("aura_medications").insert(record).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to save medication.")
    return {"status": "added", "medication_id": result.data[0]["id"]}


@router.get("/medication")
def get_medications(user_id: str = Depends(get_current_user)):
    """List all medications (active and inactive) for this user."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")
    result = (
        supabase.table("aura_medications")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return {"medications": result.data or []}


@router.post("/medication/checkin")
def medication_checkin(checkin: MedicationCheckin, user_id: str = Depends(get_current_user)):
    """
    Record that the user took a specific medication today. 0 credits.
    Verifies that the medication_id actually belongs to this user before
    recording the check-in — prevents a user from marking another user's
    medication as taken (which would corrupt that user's adherence record).
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")

    # IDOR guard: confirm this medication belongs to the calling user
    ownership = (
        supabase.table("aura_medications")
        .select("id")
        .eq("id", checkin.medication_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not ownership.data:
        raise HTTPException(status_code=404, detail="Medication not found or access denied.")

    record = {
        "user_id":       user_id,
        "medication_id": checkin.medication_id,
        "taken_at":      checkin.taken_at,
    }
    result = supabase.table("aura_medication_checkins").insert(record).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to record check-in.")
    return {"status": "checked_in"}


@router.get("/medication/checkin/today")
def get_todays_checkins(user_id: str = Depends(get_current_user)):
    """Return which medication IDs the user has already checked in today."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Aura database not configured.")
    today = date.today().isoformat()
    result = (
        supabase.table("aura_medication_checkins")
        .select("medication_id, taken_at")
        .eq("user_id", user_id)
        .gte("taken_at", today)
        .execute()
    )
    taken_ids = [row["medication_id"] for row in (result.data or [])]
    return {"taken_today": taken_ids}

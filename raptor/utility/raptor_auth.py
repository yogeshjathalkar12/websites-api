import os
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client

# Use real environment variables only -- no placeholder fallback strings.
# A fake default like "YOUR_SUPABASE_PROJECT_URL" is not a valid URL, so
# create_client() would throw at import time if the real env vars were
# ever missing -- and since every router in this app imports from this
# file, that one crash takes the entire API down on startup. Instead we
# mirror the pattern already used elsewhere in this codebase (see
# raptor_router.py / billing_router.py, which both check `if supabase:`):
# if credentials are missing, supabase stays None and callers handle it,
# rather than the whole app failing to boot.
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = (
    create_client(SUPABASE_URL, SUPABASE_KEY)
    if SUPABASE_URL and SUPABASE_KEY
    else None
)

security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verifies the JWT token from the frontend and returns the user ID."""
    if not supabase:
        # Database isn't configured -- fail clearly instead of crashing
        # with an AttributeError on `None.auth`.
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    token = credentials.credentials
    try:
        # Verify the token with Supabase Auth
        res = supabase.auth.get_user(token)
        if not res or not res.user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return res.user.id
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


def deduct_credit(user_id: str, amount: int = 1) -> int:
    """Checks if the user has enough credits, deducts them, and returns the balance."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    # 1. Fetch current credits
    res = supabase.table("raptor_users").select("credits").eq("user_id", user_id).single().execute()

    if not res.data:
        raise HTTPException(status_code=404, detail="User not found in billing system.")

    current_credits = res.data.get("credits", 0)

    # 2. Check if they have enough
    if current_credits < amount:
        raise HTTPException(status_code=402, detail="Insufficient credits to perform this action.")

    new_credits = current_credits - amount

    # 3. Update the database
    supabase.table("raptor_users").update({"credits": new_credits}).eq("user_id", user_id).execute()

    return new_credits
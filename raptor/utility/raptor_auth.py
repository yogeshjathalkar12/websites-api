import base64
import json
import logging
import os
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client

log = logging.getLogger("raptor_auth")

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


def _key_role(key: str):
    """Reads the `role` claim out of a Supabase JWT key ('anon' or
    'service_role') without verifying it - it's only used to refuse the wrong
    kind of key, not to trust anything."""
    try:
        payload = key.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def _is_service_key(key) -> bool:
    return bool(key) and (key.startswith("sb_secret_") or _key_role(key) == "service_role")


_service_client = None


def get_service_client():
    """A Supabase client holding the SERVICE-ROLE key (bypasses row-level
    security), or None if the server has none configured.

    Looks in SUPABASE_SERVICE_ROLE_KEY first, then SUPABASE_KEY - this app's
    other routers have always read the service key from SUPABASE_KEY, so a
    deployment configured the old way keeps working. A key is only accepted if
    its role claim says service_role, so a public/anon key sitting in either
    variable is never silently used for admin work."""
    global _service_client
    if _service_client is not None:
        return _service_client
    if not SUPABASE_URL:
        return None
    for name in ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY"):
        key = os.getenv(name)
        if _is_service_key(key):
            _service_client = create_client(SUPABASE_URL, key)
            return _service_client
    return None


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


LOW_CREDITS_THRESHOLD = 10


def _notify_credit_balance(user_id: str, credits_before: int, credits_after: int) -> None:
    """Fires at most one notification per deduction, only when the balance
    actually crosses a threshold (out-of-credits, or down into the low-
    credits band) - never on every single deduction, which would spam the
    bell. Best-effort: a failure here must never break the deduction itself,
    which is why this is called from deduct_credit() inside its own
    try/except rather than letting an exception propagate."""
    from .notifications import send_notification

    if credits_after <= 0 and credits_before > 0:
        send_notification(
            owner_id=user_id,
            title="You're out of credits",
            body="You've used all your Raptor credits. Top up or upgrade to keep using Pro tools.",
            type="alert",
            display_mode="banner",
            action_label="Buy credits",
            action_url="/ventures/raptor/pricing/",
        )
    elif credits_before > LOW_CREDITS_THRESHOLD >= credits_after:
        send_notification(
            owner_id=user_id,
            title="Running low on credits",
            body=f"You have {credits_after} credits left.",
            type="warning",
            action_label="Buy credits",
            action_url="/ventures/raptor/pricing/",
        )


def _billing_user_id(user_id: str, require_owner: bool = False) -> str:
    """Whose credit balance a request is charged to. A member of an
    organization spends the ORGANIZATION's pool (the owner's raptor_users
    row, which is also the org id); a removed or not-yet-accepted member
    can't spend at all. Anyone without a membership row (a solo account, or
    a database where the organization tables haven't been created yet) is
    charged to themselves exactly as before. With require_owner=True (used
    by payments) only the organization's current owner is accepted - which
    is also what lets a transferred owner pay: the credit row stays keyed by
    the organization id however ownership moves. Uses the service-role client
    because org_members has no client-readable policy for other users."""
    service_client = get_service_client()
    if not service_client:
        return user_id
    try:
        res = service_client.table("org_members").select("org_id,status,is_owner").eq("user_id", user_id).limit(1).execute()
    except Exception:
        return user_id  # org tables not there yet - behave as a solo account
    if not res.data:
        return user_id
    row = res.data[0]
    if row["status"] != "active":
        raise HTTPException(status_code=403, detail="Your access to this organization is not active.")
    if require_owner and not row.get("is_owner"):
        raise HTTPException(status_code=403, detail="Only your organization's owner can change billing.")
    return row["org_id"]


PRO_REQUIRED_MESSAGE = "This is part of the Pro plan. Upgrade to Pro to use it."


def require_pro(user_id: str, message: str = PRO_REQUIRED_MESSAGE) -> None:
    """Raises 403 unless the caller's ORGANIZATION is on the Pro plan.

    Read on the server from raptor_users.plan (the row billing writes), for the
    organization's billing row - so a team member counts as Pro when their
    owner is, and a removed member is refused. If the plan can't be read the
    answer is no, never "probably fine". This is the real lock; the screens
    that show "Upgrade to Pro" are only the friendly half."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")
    billing_id = _billing_user_id(user_id)
    try:
        rows = supabase.table("raptor_users").select("plan").eq("user_id", billing_id).limit(1).execute().data or []
    except Exception:
        raise HTTPException(status_code=502, detail="Could not verify your plan right now. Please try again.")
    if str((rows[0] if rows else {}).get("plan") or "Free").lower() != "pro":
        raise HTTPException(status_code=403, detail=message)


def pro_required(user_id: str = Depends(get_current_user)) -> str:
    """Route dependency: `@router.post(..., dependencies=[Depends(pro_required)])`."""
    require_pro(user_id)
    return user_id


def deduct_credit(user_id: str, amount: int = 1) -> int:
    """Checks if the user has enough credits, deducts them, and returns the balance."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    user_id = _billing_user_id(user_id)

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

    try:
        _notify_credit_balance(user_id, current_credits, new_credits)
    except Exception as e:
        log.error(f"Failed to send credit-balance notification for {user_id}: {e}")

    return new_credits
"""
billing_router.py — Razorpay Standard Checkout integration.

Two purchase flows live here:

  1. Pro plan upgrade (original flow)
       POST /create-order        -> order for the flat PRO_PLAN_PRICE_INR
       POST /verify-payment      -> verifies signature, sets plan=Pro,
                                     credits/total_credits = PRO_PLAN_CREDITS

  2. Credit top-ups (Pro users only)
       POST /create-topup-order  -> order for one of TOPUP_PACKS
       POST /verify-topup-payment -> verifies signature, ADDS the pack's
                                      credits on top of the user's current
                                      balance (does not touch plan)

Top-ups are priced below the per-credit rate implied by the Pro plan
price on purpose (a loyalty discount for existing Pro customers) --
which is exactly why /create-topup-order re-checks the caller's plan
server-side rather than trusting the frontend to only show the button
to Pro users. Without that check, a Free user could buy credits through
the top-up endpoint for less than the Pro plan costs and never upgrade.

Credentials: RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET must be set as real
environment variables on the server (Render dashboard -> Environment).
There is deliberately NO hardcoded fallback here -- if the env vars are
missing, billing is disabled rather than silently running on a stray
default key.
"""

import os
from datetime import datetime, timezone

import razorpay
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

# Same shared auth/credit module every other tool router uses.
from .utility.raptor_auth import get_current_user, supabase

router = APIRouter()

# ── Plan config ──────────────────────────────────────────────────────
# Single "Pro" plan for now. Change these two constants if pricing or
# credit amount changes -- nothing else in this file needs to move.
PRO_PLAN_PRICE_INR = 4999
PRO_PLAN_PRICE_PAISE = PRO_PLAN_PRICE_INR * 100
PRO_PLAN_CREDITS = 500

# ── Top-up packs (Pro users only) ───────────────────────────────────
# Priced below the Pro plan's implied ~Rs 10/credit rate as a loyalty
# discount -- larger packs get a better per-credit rate. Keep pack ids
# stable ("small"/"medium"/"large") since the frontend references them
# directly.
TOPUP_PACKS = {
    "small":  {"credits": 100, "price_inr": 700},
    "medium": {"credits": 250, "price_inr": 1500},
    "large":  {"credits": 500, "price_inr": 2500},
}

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

razorpay_client = (
    razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET
    else None
)


class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


class CreateTopupOrderRequest(BaseModel):
    pack: str  # "small" | "medium" | "large"


@router.get("/status")
def billing_status():
    return {
        "tool": "billing",
        "status": "operational" if razorpay_client else "not_configured",
        "razorpay_configured": razorpay_client is not None,
        "database_connected": supabase is not None,
    }


# ── Pro plan upgrade ─────────────────────────────────────────────────

@router.post("/create-order")
def create_order(user_id: str = Depends(get_current_user)):
    """Creates a Razorpay order for the Pro plan. Costs no credits --
    this is a checkout step, not a tool usage."""
    if not razorpay_client:
        raise HTTPException(
            status_code=500,
            detail="Payments are not configured on the server (missing RAZORPAY_KEY_ID/SECRET).",
        )

    data = {
        "amount": PRO_PLAN_PRICE_PAISE,
        "currency": "INR",
        "receipt": f"pro_{user_id[:8]}_{int(datetime.now(timezone.utc).timestamp())}",
        "notes": {"type": "pro_upgrade", "user_id": user_id},
    }

    try:
        order = razorpay_client.order.create(data=data)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to create order: {e}")

    return {
        "order_id": order["id"],
        "amount": order["amount"],
        "currency": order["currency"],
        "key_id": RAZORPAY_KEY_ID,
    }


@router.post("/verify-payment")
def verify_payment(payload: VerifyPaymentRequest, user_id: str = Depends(get_current_user)):
    """Verifies the payment signature server-side, then upgrades the
    user's plan + credits in Supabase. Never trusts the frontend's word
    that a payment succeeded -- the signature check is what actually
    proves it."""
    if not razorpay_client:
        raise HTTPException(status_code=500, detail="Payments are not configured on the server.")
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": payload.razorpay_order_id,
            "razorpay_payment_id": payload.razorpay_payment_id,
            "razorpay_signature": payload.razorpay_signature,
        })
    except razorpay.errors.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid payment signature.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Verification failed: {e}")

    try:
        supabase.table("raptor_users").update({
            "plan": "Pro",
            "total_credits": PRO_PLAN_CREDITS,
            "credits": PRO_PLAN_CREDITS,
        }).eq("user_id", user_id).execute()
    except Exception as e:
        # Signature is verified at this point -- the payment is real.
        # A DB write failure here needs a human to reconcile, not a
        # silent swallow, so we surface it distinctly from a bad signature.
        raise HTTPException(
            status_code=500,
            detail=f"Payment verified but upgrading the account failed: {e}. Contact support with this order ID: {payload.razorpay_order_id}",
        )

    return {"status": "success", "message": "Upgraded to Pro successfully!", "credits": PRO_PLAN_CREDITS}


# ── Credit top-ups (Pro users only) ─────────────────────────────────

@router.post("/create-topup-order")
def create_topup_order(payload: CreateTopupOrderRequest, user_id: str = Depends(get_current_user)):
    """Creates a Razorpay order for a credit top-up pack. Only Pro users
    may buy top-ups -- enforced here, not just hidden in the UI, since
    top-up pricing is intentionally cheaper per credit than the Pro plan
    itself and skipping this check would let Free users buy around the
    plan price."""
    if not razorpay_client:
        raise HTTPException(
            status_code=500,
            detail="Payments are not configured on the server (missing RAZORPAY_KEY_ID/SECRET).",
        )
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    pack = TOPUP_PACKS.get(payload.pack)
    if not pack:
        raise HTTPException(status_code=400, detail="Unknown credit pack.")

    try:
        user_row = (
            supabase.table("raptor_users")
            .select("plan")
            .eq("user_id", user_id)
            .single()
            .execute()
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not verify your plan: {e}")

    current_plan = (user_row.data or {}).get("plan", "Free")
    if current_plan.lower() != "pro":
        raise HTTPException(
            status_code=403,
            detail="Credit top-ups are only available on the Pro plan. Upgrade to Pro first.",
        )

    data = {
        "amount": pack["price_inr"] * 100,
        "currency": "INR",
        "receipt": f"topup_{user_id[:8]}_{int(datetime.now(timezone.utc).timestamp())}",
        # notes are the source of truth read back in verify-topup-payment --
        # never trust a client-supplied credit amount at verification time.
        "notes": {"type": "topup", "pack": payload.pack, "user_id": user_id},
    }

    try:
        order = razorpay_client.order.create(data=data)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to create order: {e}")

    return {
        "order_id": order["id"],
        "amount": order["amount"],
        "currency": order["currency"],
        "key_id": RAZORPAY_KEY_ID,
        "credits": pack["credits"],
    }


@router.post("/verify-topup-payment")
def verify_topup_payment(payload: VerifyPaymentRequest, user_id: str = Depends(get_current_user)):
    """Verifies the payment signature, then reads the pack size back from
    the order's own notes (set server-side in create-topup-order) rather
    than trusting anything the client sends -- so a tampered frontend
    request can't claim a bigger pack than was actually paid for.

    Idempotency: the raptor_topups table records every payment_id we've
    already credited. If this endpoint is ever called twice for the same
    payment (retry, double-click, flaky network), the second call is a
    no-op instead of crediting the account twice.
    """
    if not razorpay_client:
        raise HTTPException(status_code=500, detail="Payments are not configured on the server.")
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")

    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": payload.razorpay_order_id,
            "razorpay_payment_id": payload.razorpay_payment_id,
            "razorpay_signature": payload.razorpay_signature,
        })
    except razorpay.errors.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid payment signature.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Verification failed: {e}")

    # Idempotency check -- has this exact payment already been credited?
    try:
        existing = (
            supabase.table("raptor_topups")
            .select("credits")
            .eq("payment_id", payload.razorpay_payment_id)
            .execute()
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not check payment history: {e}")

    if existing.data:
        # Already processed -- return success without crediting again.
        return {
            "status": "success",
            "message": "Payment already processed.",
            "credits_added": existing.data[0]["credits"],
        }

    # Read the pack back from the order itself, not from the client.
    try:
        order = razorpay_client.order.fetch(payload.razorpay_order_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not look up order: {e}")

    notes = order.get("notes") or {}
    if notes.get("type") != "topup":
        raise HTTPException(status_code=400, detail="This order is not a credit top-up.")

    pack = TOPUP_PACKS.get(notes.get("pack"))
    if not pack:
        raise HTTPException(status_code=400, detail="Order references an unknown credit pack.")

    credits_to_add = pack["credits"]

    try:
        user_row = (
            supabase.table("raptor_users")
            .select("credits, total_credits")
            .eq("user_id", user_id)
            .single()
            .execute()
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Payment verified but reading your account failed: {e}. "
                   f"Contact support with this order ID: {payload.razorpay_order_id}",
        )

    current_credits = (user_row.data or {}).get("credits", 0) or 0
    current_total = (user_row.data or {}).get("total_credits", 0) or 0
    new_credits = current_credits + credits_to_add
    new_total = current_total + credits_to_add

    try:
        supabase.table("raptor_users").update({
            "credits": new_credits,
            "total_credits": new_total,
        }).eq("user_id", user_id).execute()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Payment verified but adding credits failed: {e}. "
                   f"Contact support with this order ID: {payload.razorpay_order_id}",
        )

    # Best-effort idempotency log -- credits are already applied above,
    # so a failure here doesn't need to fail the request, just risks not
    # catching a rare duplicate retry.
    try:
        supabase.table("raptor_topups").insert({
            "payment_id": payload.razorpay_payment_id,
            "user_id": user_id,
            "credits": credits_to_add,
        }).execute()
    except Exception:
        pass

    return {
        "status": "success",
        "message": f"Added {credits_to_add} credits!",
        "credits_added": credits_to_add,
        "credits": new_credits,
    }
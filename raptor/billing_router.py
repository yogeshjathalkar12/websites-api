"""
billing_router.py — Razorpay Standard Checkout integration.

Flow:
  1. Frontend calls POST /create-order -> we ask Razorpay for an order id.
  2. Frontend opens Razorpay's checkout modal with that order id.
  3. On success, Razorpay hands the frontend a signed payload. Frontend
     posts it to POST /verify-payment.
  4. We verify the signature with our own secret (never trust the client's
     word that a payment succeeded), then upgrade the user's plan/credits
     in Supabase.

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


@router.get("/status")
def billing_status():
    return {
        "tool": "billing",
        "status": "operational" if razorpay_client else "not_configured",
        "razorpay_configured": razorpay_client is not None,
        "database_connected": supabase is not None,
    }


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
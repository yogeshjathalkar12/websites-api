"""
security.py — the two trust models this module still needs its own logic
for. User JWT auth is NOT here anymore — now that this runs in the same
process as everything else, it reuses raptor.utility.raptor_auth.get_current_user
directly instead of duplicating it.
"""
import hashlib
import hmac
import os

from fastapi import HTTPException

_UNSUB_SECRET = os.environ.get('UNSUBSCRIBE_SIGNING_SECRET')
if not _UNSUB_SECRET:
    raise RuntimeError("UNSUBSCRIBE_SIGNING_SECRET is not set — any random 32+ char string.")


def sign_unsubscribe_token(account_id: str, email: str) -> str:
    msg = f"{account_id}:{email}".encode()
    return hmac.new(_UNSUB_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]


def verify_unsubscribe_token(account_id: str, email: str, token: str) -> bool:
    return hmac.compare_digest(sign_unsubscribe_token(account_id, email), token or '')


def verify_resend_webhook(payload_bytes: bytes, headers: dict) -> None:
    """Resend signs webhooks via svix. Requires RESEND_WEBHOOK_SECRET from
    your Resend dashboard's webhook settings."""
    from svix.webhooks import Webhook, WebhookVerificationError

    secret = os.environ.get('RESEND_WEBHOOK_SECRET')
    if not secret:
        raise HTTPException(status_code=500, detail="RESEND_WEBHOOK_SECRET is not configured on this server.")
    wh = Webhook(secret)
    try:
        wh.verify(payload_bytes, headers)
    except WebhookVerificationError:
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

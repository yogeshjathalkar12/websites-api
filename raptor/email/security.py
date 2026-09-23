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

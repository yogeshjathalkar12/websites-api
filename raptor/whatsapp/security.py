"""
security.py — Meta signs webhook payloads with header X-Hub-Signature-256:
HMAC-SHA256 of the raw request body, keyed with your Meta App Secret (a
DIFFERENT credential than any user's access token — one per Meta App,
found in the app dashboard, set once as an env var here, not something
each user brings). Without this check, anyone could POST a fake inbound
message and trigger a keyword-based auto-reply or forge an opt-out/opt-in
for a number they don't control.
"""
import hashlib
import hmac
import os

from fastapi import HTTPException

META_APP_SECRET = os.environ.get('META_APP_SECRET')
META_WEBHOOK_VERIFY_TOKEN = os.environ.get('META_WEBHOOK_VERIFY_TOKEN')  # used only for the one-time GET handshake


def verify_meta_webhook(payload_bytes: bytes, signature_header: str) -> None:
    if not META_APP_SECRET:
        raise HTTPException(status_code=500, detail="META_APP_SECRET is not configured on this server.")
    if not signature_header or not signature_header.startswith('sha256='):
        raise HTTPException(status_code=401, detail="Missing webhook signature.")
    expected = hmac.new(META_APP_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()
    provided = signature_header.split('=', 1)[1]
    if not hmac.compare_digest(expected, provided):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

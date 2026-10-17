"""Encrypts the secrets of connections (API keys, service-account files, webhook signing secrets) before they are stored.

Own key: CONNECTIONS_KEY_ENCRYPTION_SECRET (a Fernet key). If it is not set, a key is derived from EMAIL_KEY_ENCRYPTION_SECRET with
a fixed label, so connections work on the existing deployment without a new setting; set the dedicated one to separate them.
Nothing here raises at import time: a missing key only fails the request that needs it."""
import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException


def _fernet() -> Fernet:
    dedicated = os.environ.get("CONNECTIONS_KEY_ENCRYPTION_SECRET")
    if dedicated:
        return Fernet(dedicated.encode())
    base = os.environ.get("EMAIL_KEY_ENCRYPTION_SECRET")
    if not base:
        raise HTTPException(status_code=500, detail="Connections are not configured on the server (no encryption key).")
    derived = hashlib.sha256(b"raptor-connections-v1|" + base.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(raw: str) -> str:
    return _fernet().encrypt(raw.encode()).decode()


def decrypt_secret(encrypted: str) -> str:
    try:
        return _fernet().decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="A stored connection secret could not be decrypted. Reconnect it.")


def sign_state(data: dict) -> str:
    """A tamper-proof, short-lived token to carry who started a sign-in through the other service and back (Fernet is
    authenticated, and carries its own timestamp)."""
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def read_state(token: str, max_age: int = 600) -> dict:
    """The data from sign_state, or an HTTP 400 if the token is forged, damaged or older than max_age seconds."""
    try:
        return json.loads(_fernet().decrypt(token.encode(), ttl=max_age).decode())
    except (InvalidToken, ValueError):
        raise HTTPException(status_code=400, detail="This sign-in link has expired. Start again from Connections.")

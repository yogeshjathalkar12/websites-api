"""
key_vault.py — encrypted storage for user-supplied AI provider API keys

Encryption key comes from CONTENT_KEY_ENCRYPTION_SECRET, set only in Render's
env var settings — same pattern as every other secret in this deployment
(see raptor_auth.py's comment on SUPABASE_URL/SUPABASE_KEY, and the secrets
map noted in the Raptor security audit). Never committed, never a placeholder
fallback: if it's missing, key storage fails loudly instead of silently
encrypting with a guessable default.

Table (see content_schema.sql):
  user_api_keys(id, user_id, provider, encrypted_key, capabilities jsonb,
                 created_at, unique(user_id, provider))

Row-Level Security note: this table must have RLS enabled with a policy
restricting each user_id to their own rows, same as every other
user-scoped table in the Supabase schema. Confirm this before shipping —
an encrypted key an attacker can still SELECT via a missing RLS policy is
not actually protected, just obfuscated in transit to them.
"""

import os
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from raptor.utility.raptor_auth import supabase
from .providers import SUPPORTED_PROVIDERS, ProviderError, validate_key

_SECRET = os.getenv("CONTENT_KEY_ENCRYPTION_SECRET")
_fernet = Fernet(_SECRET.encode()) if _SECRET else None


def _require_fernet() -> Fernet:
    if not _fernet:
        raise HTTPException(status_code=500, detail="CONTENT_KEY_ENCRYPTION_SECRET is not configured on the server.")
    return _fernet


def _require_supabase():
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")
    return supabase


def save_key(user_id: str, provider: str, raw_api_key: str) -> dict:
    """Validates the key against the provider, encrypts it, and upserts it. Returns confirmed capabilities."""
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{provider}'.")
    if not raw_api_key or not raw_api_key.strip():
        raise HTTPException(status_code=400, detail="API key is required.")

    try:
        capabilities = validate_key(provider, raw_api_key.strip())
    except ProviderError as e:
        raise HTTPException(status_code=400, detail=str(e))

    fernet = _require_fernet()
    db = _require_supabase()

    encrypted = fernet.encrypt(raw_api_key.strip().encode()).decode()

    db.table("user_api_keys").upsert(
        {
            "user_id": user_id,
            "provider": provider,
            "encrypted_key": encrypted,
            "capabilities": capabilities,
        },
        on_conflict="user_id,provider",
    ).execute()

    return capabilities


def list_keys(user_id: str) -> list:
    """Returns provider + capabilities only — never the encrypted or raw key."""
    db = _require_supabase()
    resp = (
        db.table("user_api_keys")
        .select("provider, capabilities, created_at")
        .eq("user_id", user_id)
        .execute()
    )
    return resp.data or []


def get_decrypted_key(user_id: str, provider: str) -> str:
    db = _require_supabase()
    resp = (
        db.table("user_api_keys")
        .select("encrypted_key")
        .eq("user_id", user_id)
        .eq("provider", provider)
        .single()
        .execute()
    )
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"No saved key for provider '{provider}'. Add one first.")

    fernet = _require_fernet()
    try:
        return fernet.decrypt(resp.data["encrypted_key"].encode()).decode()
    except InvalidToken:
        # Almost always means CONTENT_KEY_ENCRYPTION_SECRET was rotated without
        # re-encrypting existing rows. Surface this clearly rather than a 500.
        raise HTTPException(status_code=500, detail="Stored key could not be decrypted — it may need to be re-added.")


def delete_key(user_id: str, provider: str) -> None:
    db = _require_supabase()
    db.table("user_api_keys").delete().eq("user_id", user_id).eq("provider", provider).execute()
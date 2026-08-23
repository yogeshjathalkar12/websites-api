"""
key_vault.py — encrypted storage for the user's own email-sending provider
credentials (Resend API key today; SMTP password once that provider is
wired for real). Own secret, EMAIL_KEY_ENCRYPTION_SECRET, kept separate
from ai_integration's CONTENT_KEY_ENCRYPTION_SECRET and whatsapp's
WHATSAPP_KEY_ENCRYPTION_SECRET even though all three now live in the same
process — a leak of one secret still shouldn't expose the other two.
"""
import os
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

_SECRET = os.environ.get('EMAIL_KEY_ENCRYPTION_SECRET')
if not _SECRET:
    raise RuntimeError(
        "EMAIL_KEY_ENCRYPTION_SECRET is not set. Generate one with: "
        "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
_fernet = Fernet(_SECRET.encode())


def encrypt_key(raw_key: str) -> str:
    return _fernet.encrypt(raw_key.encode()).decode()


def decrypt_key(encrypted_key: str) -> str:
    try:
        return _fernet.decrypt(encrypted_key.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Stored email credential could not be decrypted — it may need to be re-added.")

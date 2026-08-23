"""
key_vault.py — encrypted storage for the user's own Meta access token.
Own secret, WHATSAPP_KEY_ENCRYPTION_SECRET, isolated from the email and
content suite's secrets even though all three now share a process.
"""
import os
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

_SECRET = os.environ.get('WHATSAPP_KEY_ENCRYPTION_SECRET')
if not _SECRET:
    raise RuntimeError(
        "WHATSAPP_KEY_ENCRYPTION_SECRET is not set. Generate one with: "
        "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
_fernet = Fernet(_SECRET.encode())


def encrypt_key(raw_key: str) -> str:
    return _fernet.encrypt(raw_key.encode()).decode()


def decrypt_key(encrypted_key: str) -> str:
    try:
        return _fernet.decrypt(encrypted_key.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Stored WhatsApp credential could not be decrypted — it may need to be re-added.")

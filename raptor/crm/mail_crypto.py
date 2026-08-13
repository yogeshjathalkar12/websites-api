"""
mail_crypto.py — symmetric encryption for user SMTP credentials at rest.

Uses Fernet (AES-128-CBC + HMAC, from the `cryptography` package) rather
than storing app passwords in plaintext. The key lives ONLY in an env var
(MAILER_ENCRYPTION_KEY), never in the database, never in code.

Generate a key once, put it in your environment (Render/Vercel/.env), and
never rotate it without a migration plan (rotating it makes every
already-encrypted password undecryptable).

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os
from cryptography.fernet import Fernet, InvalidToken

_KEY = os.getenv("MAILER_ENCRYPTION_KEY")
_fernet = Fernet(_KEY.encode()) if _KEY else None


def encrypt_secret(plaintext: str) -> str:
    if not _fernet:
        raise RuntimeError(
            "MAILER_ENCRYPTION_KEY is not set on the server. "
            "Refusing to store a credential without encryption."
        )
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    if not _fernet:
        raise RuntimeError("MAILER_ENCRYPTION_KEY is not set on the server.")
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise ValueError("Could not decrypt stored credential — key mismatch or corrupted value.")
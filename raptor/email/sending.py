"""
sending.py — small shared building blocks used by every place mail
actually leaves this service: the campaign batch loop (router.py),
behavioral triggers (triggers.py), and follow-up branches
(branching.py). None of these own the account/contact SELECTION logic
— that differs enough between the three (audience tag, event match,
engagement condition) that it belongs in each file. But decrypting the
provider's API key and building an unsubscribe URL were becoming
identical copy-pasted blocks in three places, which is exactly the kind
of duplication worth pulling out before a fourth copy shows up.
"""
import os

from raptor.utility.raptor_auth import supabase
from . import key_vault
from .providers import get_provider
from .security import sign_unsubscribe_token


def unsubscribe_url(account_id: str, email: str) -> str:
    token = sign_unsubscribe_token(account_id, email)
    return f"{os.environ['APP_BASE_URL']}/unsubscribe?account={account_id}&email={email}&token={token}"


def get_ready_provider(account: dict):
    """Decrypts the account's API key and returns a ready-to-use
    provider instance. Never logs or returns the decrypted key itself —
    it only ever lives in this short-lived local dict."""
    decrypted_account = dict(account)
    decrypted_account['api_key'] = key_vault.decrypt_key(account['encrypted_api_key']) if account.get('encrypted_api_key') else None
    return get_provider(decrypted_account)


def get_or_create_contact(account_id: str, email: str) -> dict:
    """Used by triggers and sequence enrollment: both sources often
    describe someone who isn't in your list yet — a Shopify buyer, a
    brand-new signup, an email typed into an enroll form. Auto-provision
    a minimal email_contacts row so the send still goes out instead of
    silently dropping it."""
    existing = (
        supabase.table('email_contacts')
        .select('*')
        .eq('account_id', account_id)
        .eq('email', email)
        .limit(1)
        .execute()
        .data
    )
    if existing:
        return existing[0]
    created = supabase.table('email_contacts').insert({'account_id': account_id, 'email': email}).execute().data
    return created[0]
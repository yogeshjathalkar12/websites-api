"""
tests/test_email_desktop_mailbox.py — a desktop account can carry the whole mailbox (settings + encrypted password)
so the web app and the desktop app share one source of truth.

No network or database: the same fakes the other email tests use.
"""
import os

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException, Response

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('UNSUBSCRIBE_SIGNING_SECRET', 'u' * 40)
os.environ.setdefault('EMAIL_TRACKING_SIGNING_SECRET', 't' * 40)
os.environ.setdefault('APP_BASE_URL', 'https://example.test')

from raptor.email import key_vault, providers  # noqa: E402
from raptor.email import router as email_router  # noqa: E402
from raptor.utility import raptor_auth  # noqa: E402
from tests.test_email_providers import FakeDB, PUBLIC_IP, _resolve_to  # noqa: E402

CONFIG = {'host': 'smtp.gmail.com', 'port': 587, 'username': 'me@example.com', 'security': 'starttls',
          'imap_host': 'imap.gmail.com', 'signature': 'Me, Example Ltd, Pune', 'weekdays_only': True, 'icp_threshold': 70}
FULL = {'label': 'Gmail outreach', 'provider': 'desktop', 'from_email': 'me@example.com', 'from_name': 'Me',
        'api_key': 'app-password-123', 'smtp_config': CONFIG, 'accepted_risks_version': email_router.RISKS_VERSION,
        'daily_cap': 10, 'warmup_target': 20, 'hours_start': 9, 'hours_end': 19}


@pytest.fixture(autouse=True)
def smtp_off(monkeypatch):
    monkeypatch.delenv('EMAIL_SMTP_ENABLED', raising=False)
    _resolve_to(monkeypatch, PUBLIC_IP)
    # This server cannot reach mail servers: creating a desktop mailbox must never try to log in.
    monkeypatch.setattr(providers.SmtpProvider, 'check_connection', lambda self: (_ for _ in ()).throw(AssertionError('logged in')))


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB({'raptor_users': [{'plan': 'Pro'}]})
    monkeypatch.setattr(email_router, 'supabase', fake)
    monkeypatch.setattr(raptor_auth, 'supabase', fake)
    return fake


def _create(payload):
    return email_router.create_account(payload, user_id='user-1')


# ───────────────────────── saving the whole mailbox ─────────────────────────

def test_the_mailbox_is_saved_with_an_encrypted_password_and_its_settings(db):
    account = _create(dict(FULL))
    row = db.inserted('email_accounts')[0]
    assert row['provider'] == 'desktop' and row['owner_id'] == 'user-1'
    assert row['encrypted_api_key'] and 'app-password-123' not in str(row)          # never the plain password
    assert key_vault.decrypt_key(row['encrypted_api_key']) == 'app-password-123'
    assert row['smtp_config']['host'] == 'smtp.gmail.com' and row['smtp_config']['imap_host'] == 'imap.gmail.com'
    assert row['smtp_config']['signature'] == 'Me, Example Ltd, Pune' and row['smtp_config']['weekdays_only'] is True
    assert 'password' not in row['smtp_config']
    assert (row['daily_cap'], row['warmup_target'], row['business_hours_start'], row['business_hours_end']) == (10, 20, 9, 19)
    assert 'encrypted_api_key' not in account                                       # and never sent back to the browser


def test_the_sending_rules_come_from_the_form(db):
    _create({**FULL, 'daily_cap': 5, 'warmup_target': 40, 'hours_start': 8, 'hours_end': 17})
    row = db.inserted('email_accounts')[0]
    assert (row['daily_cap'], row['warmup_target'], row['business_hours_start'], row['business_hours_end']) == (5, 40, 8, 17)


@pytest.mark.parametrize('change, fragment', [
    ({'hours_start': 19, 'hours_end': 9}, 'end hour'),
    ({'daily_cap': 0}, 'first-day limit'),
    ({'daily_cap': 30, 'warmup_target': 20}, 'daily maximum'),
    ({'smtp_config': {**CONFIG, 'host': 'not a host'}}, 'host name'),
    ({'smtp_config': {**CONFIG, 'imap_host': 'bad host!'}}, 'inbox server'),
    ({'smtp_config': {**CONFIG, 'imap_port': 25}}, 'inbox port'),
    ({'smtp_config': {**CONFIG, 'signature': 'x' * 601}}, 'too long'),
    ({'smtp_config': {**CONFIG, 'icp_threshold': 150}}, 'between 0 and 100'),
])
def test_bad_settings_are_refused_with_a_clear_message_and_nothing_is_saved(db, change, fragment):
    with pytest.raises(HTTPException) as err:
        _create({**FULL, **change})
    assert err.value.status_code == 400 and fragment in err.value.detail
    assert db.inserted('email_accounts') == []


def test_the_responsibilities_statement_is_still_required(db):
    with pytest.raises(HTTPException) as err:
        _create({**FULL, 'accepted_risks_version': 'old'})
    assert err.value.status_code == 400 and db.inserted('email_accounts') == []


def test_a_desktop_account_without_a_password_still_works_the_old_way(db):
    payload = {k: v for k, v in FULL.items() if k not in ('api_key', 'smtp_config')}
    _create(payload)
    row = db.inserted('email_accounts')[0]
    assert row['encrypted_api_key'] == '' and row['smtp_config'] is None and row['daily_cap'] == 10


# ───────────────────────── the desktop app fetching it ─────────────────────────

def test_the_owner_can_fetch_the_mailbox_and_it_is_never_cached(db):
    stored = {'id': 'acct-1', 'owner_id': 'user-1', 'provider': 'desktop', 'label': 'Gmail outreach',
              'from_email': 'me@example.com', 'from_name': 'Me', 'smtp_config': CONFIG,
              'encrypted_api_key': key_vault.encrypt_key('app-password-123'),
              'daily_cap': 10, 'warmup_target': 20, 'business_hours_start': 9, 'business_hours_end': 19}
    db.data['email_accounts'] = [stored]
    response = Response()
    out = email_router.get_mailbox_credentials('acct-1', response, user_id='user-1')
    assert out['password'] == 'app-password-123' and out['smtp_config']['imap_host'] == 'imap.gmail.com'
    assert out['business_hours_end'] == 19
    assert response.headers['cache-control'] == 'no-store'


def test_an_account_without_a_stored_password_has_nothing_to_fetch(db):
    db.data['email_accounts'] = [{'id': 'acct-1', 'owner_id': 'user-1', 'provider': 'desktop', 'encrypted_api_key': ''}]
    with pytest.raises(HTTPException) as err:
        email_router.get_mailbox_credentials('acct-1', Response(), user_id='user-1')
    assert err.value.status_code == 404


def test_an_unknown_or_someone_elses_account_is_a_404(db):
    db.data['email_accounts'] = []          # the owner filter finds nothing for another user's account
    with pytest.raises(HTTPException) as err:
        email_router.get_mailbox_credentials('acct-9', Response(), user_id='user-2')
    assert err.value.status_code == 404


def test_the_free_plan_cannot_fetch(db):
    db.data['raptor_users'] = [{'plan': 'Free'}]
    with pytest.raises(HTTPException) as err:
        email_router.get_mailbox_credentials('acct-1', Response(), user_id='user-1')
    assert err.value.status_code in (402, 403)

"""
tests/test_email_relay.py — the "desktop" sender: mail written in the web app waits in email_relay_queue
and the user's desktop app sends it (see db/migrations/2026-10-10_email_relay.sql, whose database side is
tested separately against a real Postgres).

No network or database: the Supabase client is replaced with the same fake the provider tests use.
"""
import os

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('UNSUBSCRIBE_SIGNING_SECRET', 'u' * 40)
os.environ.setdefault('EMAIL_TRACKING_SIGNING_SECRET', 't' * 40)
os.environ.setdefault('APP_BASE_URL', 'https://example.test')

from raptor.email import providers, sending  # noqa: E402
from raptor.email import router as email_router  # noqa: E402
from raptor.utility import raptor_auth  # noqa: E402
from tests.test_email_providers import FakeDB  # noqa: E402

DESKTOP_ACCOUNT = {'id': 'acct-d', 'owner_id': 'user-1', 'from_email': 'me@example.com', 'from_name': 'Me',
                   'provider': 'desktop', 'encrypted_api_key': '', 'daily_cap': 10, 'warmup_target': 20}


@pytest.fixture(autouse=True)
def smtp_off(monkeypatch):
    """The real situation this exists for: the server cannot send over SMTP."""
    monkeypatch.delenv('EMAIL_SMTP_ENABLED', raising=False)


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(raptor_auth, 'supabase', fake)
    monkeypatch.setattr(email_router, 'supabase', fake)
    return fake


# ───────────────────────── the provider ─────────────────────────

def test_sending_queues_the_email_for_the_account_owners_desktop(db):
    provider = providers.get_provider(DESKTOP_ACCOUNT)
    assert isinstance(provider, providers.DesktopRelayProvider)
    message_id = provider.send('me@example.com', 'Me', 'you@there.com', 'Hello', '<p>Hi</p>')
    row = db.inserted('email_relay_queue')[0]
    assert row == {'user_id': 'user-1', 'account_id': 'acct-d', 'to_email': 'you@there.com',
                   'subject': 'Hello', 'body_html': '<p>Hi</p>'}
    assert message_id == 'email_relay_queue-1'  # the queue row's id, which is how results find their way back


def test_the_row_carries_no_credentials_and_leaves_timing_to_the_database(db):
    providers.get_provider(DESKTOP_ACCOUNT).send('me@example.com', 'Me', 'you@there.com', 'S', '<p>x</p>')
    row = db.inserted('email_relay_queue')[0]
    # send_after / expires_at are left to the column defaults: due now, expires 48h later.
    assert not {'send_after', 'expires_at', 'status', 'password', 'api_key'} & set(row)


def test_a_desktop_account_needs_an_owner_and_an_id():
    with pytest.raises(ValueError):
        providers.get_provider({'provider': 'desktop', 'id': 'a'})


def test_queueing_failures_pause_the_campaign_instead_of_failing_every_recipient(monkeypatch):
    class Broken:
        def table(self, name):
            raise ConnectionError('database down')
    monkeypatch.setattr(raptor_auth, 'supabase', Broken())
    with pytest.raises(providers.ProviderRateLimited):  # the campaign loop treats this as "try later"
        providers.get_provider(DESKTOP_ACCOUNT).send('a@b.co', 'A', 'c@d.co', 'S', 'B')


def test_no_database_is_also_a_pause_not_a_crash(monkeypatch):
    monkeypatch.setattr(raptor_auth, 'supabase', None)
    with pytest.raises(providers.ProviderUnavailable):
        providers.get_provider(DESKTOP_ACCOUNT).send('a@b.co', 'A', 'c@d.co', 'S', 'B')


def test_sending_gets_a_provider_without_trying_to_decrypt_a_password(db):
    # A desktop account stores '' as its secret; get_ready_provider must not choke on it.
    assert isinstance(sending.get_ready_provider(DESKTOP_ACCOUNT), providers.DesktopRelayProvider)


# ───────────────────────── creating the account ─────────────────────────

DESKTOP_BASE = {'label': 'My desktop', 'from_email': 'me@example.com', 'from_name': 'Me', 'provider': 'desktop',
                'accepted_risks_version': email_router.RISKS_VERSION}


@pytest.fixture
def pro(monkeypatch):
    monkeypatch.setattr(email_router, '_require_pro', lambda user_id: None)


def _create(payload):
    return email_router.create_account(payload, user_id='user-1')


def test_a_desktop_account_can_be_created_while_smtp_is_off_and_needs_no_password(db, pro):
    _create(DESKTOP_BASE)
    row = db.inserted('email_accounts')[0]
    assert row['provider'] == 'desktop' and row['owner_id'] == 'user-1'
    assert row['encrypted_api_key'] == '' and row['smtp_config'] is None
    assert (row['daily_cap'], row['warmup_target']) == (10, 20)


def test_a_desktop_account_still_requires_pro(db, monkeypatch):
    def deny(user_id):
        raise HTTPException(status_code=403, detail='Pro only')
    monkeypatch.setattr(email_router, '_require_pro', deny)
    with pytest.raises(HTTPException) as err:
        _create(DESKTOP_BASE)
    assert err.value.status_code == 403 and db.inserted('email_accounts') == []


def test_a_desktop_account_still_needs_the_responsibilities_confirmation(db, pro):
    with pytest.raises(HTTPException) as err:
        _create({**DESKTOP_BASE, 'accepted_risks_version': 'not-the-current-wording'})
    assert err.value.status_code == 400 and db.inserted('email_accounts') == []
    row_time = None
    _create(DESKTOP_BASE)
    row = db.inserted('email_accounts')[0]
    assert row['risks_accepted_version'] == email_router.RISKS_VERSION and row['risks_accepted_at']
    assert row_time is None


def test_a_smtp_account_still_needs_its_password_and_the_server_switch(db, pro):
    smtp = {**DESKTOP_BASE, 'provider': 'smtp', 'smtp_config': {'host': 'smtp.example.com', 'username': 'u'}}
    with pytest.raises(HTTPException) as err:
        _create(smtp)  # no api_key
    assert err.value.status_code == 400 and 'api_key' in err.value.detail
    with pytest.raises(HTTPException) as err:
        _create({**smtp, 'api_key': 'pw'})  # SMTP switch is off
    assert err.value.status_code == 400 and 'switched on' in err.value.detail


def test_the_providers_endpoint_says_desktop_is_always_available():
    body = email_router.available_providers(user_id='u')
    assert body['desktop'] is True and body['smtp'] is False


# ───────────────────────── the whole send loop through the relay ─────────────────────────

CAMPAIGN = {'id': 'camp-1', 'account_id': 'acct-d', 'status': 'sending', 'subject': 'Hi {{first_name}}',
            'body_html': '<p>Hello <a href="https://shoonyaorigins.com">our site</a></p><a href="{{unsubscribe_url}}">unsubscribe</a>',
            'email_accounts': DESKTOP_ACCOUNT}


def _contacts(n):
    return [{'id': f'r{i}', 'email_contacts': {'email': f'p{i}@x.test', 'first_name': f'P{i}'}} for i in range(n)]


@pytest.fixture
def loop(monkeypatch):
    fake = FakeDB({'email_campaigns': [CAMPAIGN], 'email_campaign_variants': [], 'email_suppressions': [],
                   'email_campaign_recipients': _contacts(3)})
    monkeypatch.setattr(raptor_auth, 'supabase', fake)
    monkeypatch.setattr(email_router, 'supabase', fake)
    monkeypatch.setattr(email_router, 'within_business_hours', lambda a: True)
    monkeypatch.setattr(email_router, 'todays_allowed_volume', lambda a: 100)
    monkeypatch.setattr(email_router, 'sent_today_count', lambda a: 0)
    monkeypatch.setattr(email_router, '_try_acquire_lock', lambda cid: True)
    monkeypatch.setattr(email_router, '_release_lock', lambda cid: None)
    monkeypatch.setattr(email_router, '_ensure_recipients_populated', lambda c: None)
    email_router._provider_backoff_until.clear()
    return fake


def test_a_campaign_batch_queues_rendered_mail_instead_of_sending_it(loop):
    result = email_router._send_one_batch('camp-1')
    assert result['sent'] == 3 and result['failed'] == 0
    queued = loop.inserted('email_relay_queue')
    assert [q['to_email'] for q in queued] == ['p0@x.test', 'p1@x.test', 'p2@x.test']
    first = queued[0]
    assert first['subject'] == 'Hi P0'                                   # merge tags already filled in
    assert 'unsubscribe?account=acct-d' in first['body_html']           # the unsubscribe link is in the mail
    assert '/track/open' in first['body_html'] and '/track/click' in first['body_html']  # so are open/click tracking
    assert '{{' not in first['subject'] + first['body_html']
    # every recipient row records the queue row id, so a later failure/bounce can find it again
    sent_updates = [u for u in loop.updates('email_campaign_recipients') if u.get('status') == 'sent']
    assert len(sent_updates) == 3 and all(u['provider_message_id'] == 'email_relay_queue-1' for u in sent_updates)
    # "sent" events still count toward the web side's daily pace
    assert len(loop.inserted('email_events')) == 3


def test_a_database_outage_while_queueing_pauses_the_campaign(loop, monkeypatch):
    class Down:
        def table(self, name):
            if name == 'email_relay_queue':
                raise ConnectionError('down')
            return loop.table(name)
    monkeypatch.setattr(raptor_auth, 'supabase', Down())
    result = email_router._send_one_batch('camp-1')
    assert result['paused'] == 'provider_rate_limited' and result['failed'] == 0 and result['sent'] == 0

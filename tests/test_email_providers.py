"""
tests/test_email_providers.py — the email module's provider layer.

Covers the SMTP provider (settings validation, TLS, message shape, error
classification), the Resend provider (rate-limit mapping and the
cross-customer API-key race), account creation defaults, and the send
loop's "provider limit reached -> pause, don't fail" behaviour.

No real network, mail server or database is used: smtplib, DNS and the
Supabase client are replaced with fakes.
"""
import os
import smtplib
import ssl
import threading
import time
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

# The router imports modules that read these at import time.
os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('UNSUBSCRIBE_SIGNING_SECRET', 'u' * 40)
os.environ.setdefault('EMAIL_TRACKING_SIGNING_SECRET', 't' * 40)
os.environ.setdefault('APP_BASE_URL', 'https://example.test')

import resend  # noqa: E402

from raptor.email import providers, key_vault  # noqa: E402
from raptor.email import router as email_router  # noqa: E402

PUBLIC_IP = '93.184.216.34'


def _resolve_to(monkeypatch, ip):
    """Make every host name resolve to `ip`."""
    monkeypatch.setattr(providers.socket, 'getaddrinfo', lambda host, *a, **k: [(2, 1, 6, '', (ip, 0))])


GOOD = {'host': 'SMTP.Example.com', 'port': 587, 'username': 'me@example.com', 'security': 'starttls'}


# ───────────────────────── validate_smtp_config ─────────────────────────

def test_valid_config_is_normalised(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_IP)
    assert providers.validate_smtp_config(GOOD) == {
        'host': 'smtp.example.com', 'port': 587, 'username': 'me@example.com', 'security': 'starttls'}


def test_port_defaults_follow_the_connection_type(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_IP)
    assert providers.validate_smtp_config({**GOOD, 'port': None, 'security': 'ssl'})['port'] == 465
    assert providers.validate_smtp_config({**GOOD, 'port': '', 'security': 'starttls'})['port'] == 587


def test_config_never_carries_a_password(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_IP)
    out = providers.validate_smtp_config({**GOOD, 'password': 'hunter2'})
    assert 'password' not in out


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.5', '192.168.1.10', '172.16.0.9',
                                '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1',
                                '::ffff:10.0.0.1'])
def test_internal_addresses_are_refused(monkeypatch, ip):
    """The server connects on the customer's behalf, so it must never be
    pointable at localhost, private networks or cloud metadata."""
    _resolve_to(monkeypatch, ip)
    with pytest.raises(ValueError, match="isn't allowed"):
        providers.validate_smtp_config(GOOD)


def test_a_host_resolving_to_any_internal_address_is_refused(monkeypatch):
    monkeypatch.setattr(providers.socket, 'getaddrinfo', lambda *a, **k: [
        (2, 1, 6, '', (PUBLIC_IP, 0)), (2, 1, 6, '', ('10.1.1.1', 0))])
    with pytest.raises(ValueError, match="isn't allowed"):
        providers.validate_smtp_config(GOOD)


def test_unresolvable_host_gives_a_friendly_error(monkeypatch):
    def boom(*a, **k):
        raise providers.socket.gaierror('nope')
    monkeypatch.setattr(providers.socket, 'getaddrinfo', boom)
    with pytest.raises(ValueError, match="couldn't find a mail server"):
        providers.validate_smtp_config(GOOD)


@pytest.mark.parametrize('bad', [
    {'host': ''}, {'host': 'localhost'}, {'host': 'https://smtp.example.com'},
    {'host': 'smtp.example.com/evil'}, {'host': 'user@smtp.example.com'}, {'host': 'a b.com'},
    {'port': 22}, {'port': 3306}, {'port': 6379}, {'port': 'abc'},
    {'security': 'none'}, {'security': 'plain'},
    {'username': ''}, {'username': '   '},
])
def test_bad_settings_are_rejected(monkeypatch, bad):
    _resolve_to(monkeypatch, PUBLIC_IP)
    with pytest.raises(ValueError):
        providers.validate_smtp_config({**GOOD, **bad})


def test_non_dict_config_is_rejected():
    with pytest.raises(ValueError):
        providers.validate_smtp_config(None)


# ───────────────────────── SmtpProvider ─────────────────────────

class FakeSMTP:
    """Stands in for smtplib.SMTP / SMTP_SSL and records what was done."""
    instances = []
    login_error = None
    connect_error = None
    send_error = None

    def __init__(self, host, port, timeout=None, context=None):
        if FakeSMTP.connect_error:
            raise FakeSMTP.connect_error
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls, self.sent = [], []
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append('ehlo')

    def starttls(self, context=None):
        self.calls.append('starttls')
        self.starttls_context = context

    def login(self, user, password):
        if FakeSMTP.login_error:
            raise FakeSMTP.login_error
        self.calls.append('login')
        self.credentials = (user, password)

    def send_message(self, msg, from_addr=None, to_addrs=None):
        if FakeSMTP.send_error:
            raise FakeSMTP.send_error
        self.sent.append((msg, from_addr, to_addrs))

    def quit(self):
        self.calls.append('quit')


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances, FakeSMTP.login_error, FakeSMTP.connect_error, FakeSMTP.send_error = [], None, None, None
    _resolve_to(monkeypatch, PUBLIC_IP)
    monkeypatch.setattr(providers.smtplib, 'SMTP', FakeSMTP)
    monkeypatch.setattr(providers.smtplib, 'SMTP_SSL', FakeSMTP)
    return FakeSMTP


def _provider(**over):
    cfg = {'host': 'smtp.example.com', 'port': 587, 'username': 'me@example.com',
           'security': 'starttls', 'password': 's3cret', **over}
    return providers.SmtpProvider(cfg)


def test_smtp_send_uses_starttls_with_certificate_checking(fake_smtp):
    _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>Hello</p>')
    s = fake_smtp.instances[0]
    assert s.calls == ['ehlo', 'starttls', 'ehlo', 'login', 'quit']
    assert s.credentials == ('me@example.com', 's3cret')
    assert s.timeout == providers.SMTP_TIMEOUT_SECONDS
    assert s.starttls_context.verify_mode == ssl.CERT_REQUIRED and s.starttls_context.check_hostname


def test_smtp_ssl_mode_connects_encrypted_from_the_start(fake_smtp):
    _provider(security='ssl', port=465).send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>x</p>')
    s = fake_smtp.instances[0]
    assert 'starttls' not in s.calls and s.context.verify_mode == ssl.CERT_REQUIRED and s.port == 465


def test_message_is_multipart_with_text_and_html_and_a_message_id(fake_smtp):
    html = '<p>Hi <b>there</b></p><p><a href="https://x.test/a?b=1">Book a call</a></p><img src="https://t.test/p.gif">'
    msg_id = _provider().send('me@example.com', 'Me Q. Sender', 'you@there.com', 'Hello', html)
    msg, from_addr, to_addrs = fake_smtp.instances[0].sent[0]
    assert (from_addr, to_addrs) == ('me@example.com', ['you@there.com'])
    assert msg['To'] == 'you@there.com' and msg['Subject'] == 'Hello'
    assert 'Me Q. Sender' in msg['From'] and 'me@example.com' in msg['From']
    assert msg.get_content_type() == 'multipart/alternative'
    kinds = [p.get_content_type() for p in msg.iter_parts()]
    assert kinds == ['text/plain', 'text/html']
    text = msg.get_body(preferencelist=('plain',)).get_content()
    assert 'Book a call (https://x.test/a?b=1)' in text and '<' not in text
    assert msg['Message-ID'] == msg_id and msg_id.endswith('@example.com>')


def test_header_injection_is_impossible(fake_smtp):
    with pytest.raises(ValueError):
        _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi\r\nBcc: evil@x.com', '<p>x</p>')
    assert not fake_smtp.instances or not fake_smtp.instances[0].sent


def test_send_rechecks_the_host_at_send_time(monkeypatch, fake_smtp):
    _resolve_to(monkeypatch, '10.0.0.1')  # DNS now points somewhere internal
    with pytest.raises(ValueError, match="isn't allowed"):
        _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>x</p>')
    assert fake_smtp.instances == []


def test_wrong_password_gives_a_helpful_message(fake_smtp):
    fake_smtp.login_error = smtplib.SMTPAuthenticationError(535, b'nope')
    with pytest.raises(RuntimeError, match='app password'):
        _provider().check_connection()


def test_unreachable_server_mentions_blocked_ports(fake_smtp):
    fake_smtp.connect_error = TimeoutError('timed out')
    with pytest.raises(providers.ProviderUnavailable, match='blocks outgoing mail ports'):
        _provider().check_connection()


def test_unreachable_server_during_send_pauses_instead_of_failing(fake_smtp):
    """A blocked port must never look like a bad recipient."""
    fake_smtp.connect_error = TimeoutError('timed out')
    with pytest.raises(providers.ProviderRateLimited):  # ProviderUnavailable is a kind of this
        _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>x</p>')


def test_port_2525_error_does_not_blame_the_port(fake_smtp):
    fake_smtp.connect_error = ConnectionRefusedError('refused')
    with pytest.raises(providers.ProviderUnavailable) as err:
        _provider(port=2525).check_connection()
    assert 'blocks outgoing mail ports' not in str(err.value)


def test_check_connection_sends_nothing(fake_smtp):
    _provider().check_connection()
    s = fake_smtp.instances[0]
    assert s.sent == [] and s.calls[-2:] == ['login', 'quit']


@pytest.mark.parametrize('code,text', [
    (421, b'4.7.0 Try again later'),
    (452, b'4.5.3 Too many recipients'),
    (550, b'5.4.5 Daily user sending limit exceeded'),
    (550, b'5.7.60 Sending quota exceeded for this mailbox'),
    (554, b'5.2.0 Message rate limited, too many messages'),
])
def test_sender_level_limits_become_rate_limited(fake_smtp, code, text):
    fake_smtp.send_error = smtplib.SMTPResponseException(code, text)
    with pytest.raises(providers.ProviderRateLimited):
        _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>x</p>')


@pytest.mark.parametrize('code,text', [
    (550, b'5.1.1 The email account that you tried to reach does not exist'),
    (553, b'5.1.3 Invalid recipient address'),
    (451, b'4.3.0 Temporary local problem, greylisted'),
    (554, b'5.7.1 Message rejected as spam'),
])
def test_recipient_level_errors_are_real_failures(fake_smtp, code, text):
    fake_smtp.send_error = smtplib.SMTPResponseException(code, text)
    with pytest.raises(RuntimeError, match='refused the message') as err:
        _provider().send('me@example.com', 'Me', 'you@there.com', 'Hi', '<p>x</p>')
    assert not isinstance(err.value, providers.ProviderRateLimited)


def test_smtp_needs_every_setting():
    with pytest.raises(ValueError, match='password'):
        providers.SmtpProvider({'host': 'a.b', 'port': 587, 'username': 'u', 'security': 'starttls'})


# ───────────────────────── ResendProvider ─────────────────────────

def test_resend_success_returns_the_id(monkeypatch):
    monkeypatch.setattr(resend.Emails, 'send', staticmethod(lambda payload: {'id': 'abc123'}))
    assert providers.ResendProvider('re_key').send('a@b.co', 'A', 'c@d.co', 'S', '<p>x</p>') == 'abc123'


@pytest.mark.parametrize('make', [
    lambda: resend.exceptions.RateLimitError(message='Too many', error_type='rate_limit_exceeded', code=429),
    lambda: resend.exceptions.RateLimitError(message='Daily quota', error_type='daily_quota_exceeded', code=429),
    lambda: resend.exceptions.ResendError(code=429, error_type='monthly_quota_exceeded', message='m', suggested_action='s'),
])
def test_resend_limits_become_rate_limited(monkeypatch, make):
    def raiser(payload):
        raise make()
    monkeypatch.setattr(resend.Emails, 'send', staticmethod(raiser))
    with pytest.raises(providers.ProviderRateLimited):
        providers.ResendProvider('re_key').send('a@b.co', 'A', 'c@d.co', 'S', '<p>x</p>')


def test_other_resend_errors_are_not_treated_as_limits(monkeypatch):
    def raiser(payload):
        raise resend.exceptions.ResendError(code=403, error_type='invalid_api_key', message='bad key', suggested_action='fix')
    monkeypatch.setattr(resend.Emails, 'send', staticmethod(raiser))
    with pytest.raises(resend.exceptions.ResendError):
        providers.ResendProvider('re_key').send('a@b.co', 'A', 'c@d.co', 'S', '<p>x</p>')


def test_concurrent_sends_never_use_another_customers_key(monkeypatch):
    """Regression: the Resend SDK holds the key in a module global, so two
    threads sending for two customers could cross keys."""
    seen = []

    def slow_send(payload):
        key_at_call = resend.api_key
        time.sleep(0.005)  # let other threads run between setting the key and using it
        seen.append((payload['to'][0], key_at_call, resend.api_key))
        return {'id': 'x'}
    monkeypatch.setattr(resend.Emails, 'send', staticmethod(slow_send))

    def worker(i):
        key = f're_customer_{i % 2}'
        providers.ResendProvider(key).send('a@b.co', 'A', f'{i % 2}@d.co', 'S', '<p>x</p>')

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(seen) == 24
    for to, key_at_call, key_after in seen:
        assert key_at_call == f're_customer_{to[0]}' and key_after == key_at_call


# ───────────────────────── get_provider ─────────────────────────

def test_get_provider_builds_each_kind():
    assert isinstance(providers.get_provider({'provider': 'resend', 'api_key': 'k'}), providers.ResendProvider)
    smtp = providers.get_provider({'provider': 'smtp', 'api_key': 'pw', 'smtp_config': {
        'host': 'smtp.example.com', 'port': 587, 'username': 'u', 'security': 'starttls'}})
    assert isinstance(smtp, providers.SmtpProvider) and smtp.config['password'] == 'pw'
    with pytest.raises(ValueError):
        providers.get_provider({'provider': 'carrier-pigeon', 'api_key': 'k'})


# ───────────────────────── fake database for router tests ─────────────────────────

class FakeQuery:
    def __init__(self, db, table):
        self.db, self.table, self.op, self.payload = db, table, 'select', None

    def select(self, *a, **k):
        self.op = 'select'
        return self

    def insert(self, payload):
        self.op, self.payload = 'insert', payload
        return self

    def update(self, payload):
        self.op, self.payload = 'update', payload
        return self

    def __getattr__(self, name):  # eq / in_ / gte / or_ / order / limit / single ...
        return lambda *a, **k: self

    def execute(self):
        self.db.log.append((self.table, self.op, self.payload))
        rows = self.db.data.get(self.table, [])
        if self.op == 'insert':
            row = {'id': f'{self.table}-1', **(self.payload if isinstance(self.payload, dict) else {})}
            return type('R', (), {'data': [row], 'count': 1})()
        if self.op == 'update':
            return type('R', (), {'data': rows or [{'id': 'x'}], 'count': 1})()
        data = rows[0] if self.table in self.db.single_tables else rows
        return type('R', (), {'data': data, 'count': len(rows)})()


class FakeDB:
    single_tables = {'email_campaigns'}

    def __init__(self, data=None):
        self.data, self.log = data or {}, []

    def table(self, name):
        return FakeQuery(self, name)

    def inserted(self, table):
        return [p for t, op, p in self.log if t == table and op == 'insert']

    def updates(self, table):
        return [p for t, op, p in self.log if t == table and op == 'update']


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(email_router, 'supabase', fake)
    return fake


def _create(payload):
    return email_router.create_account(payload, user_id='user-1')


BASE = {'label': 'L', 'from_email': 'me@example.com', 'from_name': 'Me', 'api_key': 'secret-key'}


@pytest.fixture
def smtp_on(monkeypatch):
    monkeypatch.setenv('EMAIL_SMTP_ENABLED', 'true')


@pytest.fixture(autouse=True)
def smtp_off_unless_asked(monkeypatch):
    """The real default: SMTP is off. Tests that need it request smtp_on."""
    monkeypatch.delenv('EMAIL_SMTP_ENABLED', raising=False)


# ───────────────────────── account creation ─────────────────────────

def test_resend_free_defaults_fit_the_free_plan(db):
    _create({**BASE})
    row = db.inserted('email_accounts')[0]
    assert (row['daily_cap'], row['warmup_target']) == (20, 100) and row['provider'] == 'resend'


def test_resend_paid_plan_gets_a_higher_ceiling(db):
    _create({**BASE, 'plan': 'paid'})
    row = db.inserted('email_accounts')[0]
    assert (row['daily_cap'], row['warmup_target']) == (20, 300)


def test_unknown_plan_falls_back_to_the_safe_free_limits(db):
    _create({**BASE, 'plan': 'enterprise-unlimited'})
    assert db.inserted('email_accounts')[0]['warmup_target'] == 100


def test_smtp_account_stores_settings_but_encrypts_the_password(db, monkeypatch, smtp_on):
    _resolve_to(monkeypatch, PUBLIC_IP)
    _create({**BASE, 'api_key': 'mailbox-pass', 'provider': 'smtp', 'smtp_config': {**GOOD, 'password': 'leak?'}})
    row = db.inserted('email_accounts')[0]
    assert row['provider'] == 'smtp' and (row['daily_cap'], row['warmup_target']) == (10, 40)
    assert row['smtp_config'] == {'host': 'smtp.example.com', 'port': 587, 'username': 'me@example.com', 'security': 'starttls'}
    assert 'mailbox-pass' not in str(row) and 'leak?' not in str(row)
    assert key_vault.decrypt_key(row['encrypted_api_key']) == 'mailbox-pass'


def test_smtp_with_bad_settings_is_a_400_and_saves_nothing(db, monkeypatch, smtp_on):
    _resolve_to(monkeypatch, '127.0.0.1')
    with pytest.raises(HTTPException) as err:
        _create({**BASE, 'provider': 'smtp', 'smtp_config': GOOD})
    assert err.value.status_code == 400 and db.inserted('email_accounts') == []


def test_unknown_provider_is_a_400(db):
    with pytest.raises(HTTPException) as err:
        _create({**BASE, 'provider': 'sendgrid'})
    assert err.value.status_code == 400 and 'resend, smtp' in err.value.detail


def test_smtp_test_endpoint_reports_success_and_failure(monkeypatch, smtp_on):
    _resolve_to(monkeypatch, PUBLIC_IP)
    monkeypatch.setattr(providers.SmtpProvider, 'check_connection', lambda self: None)
    assert email_router.test_smtp_connection({'smtp_config': GOOD, 'password': 'pw'}, user_id='u') == {'ok': True}

    def fail(self):
        raise RuntimeError('The mail server rejected the username or password.')
    monkeypatch.setattr(providers.SmtpProvider, 'check_connection', fail)
    with pytest.raises(HTTPException) as err:
        email_router.test_smtp_connection({'smtp_config': GOOD, 'password': 'pw'}, user_id='u')
    assert err.value.status_code == 400 and 'rejected' in err.value.detail

    with pytest.raises(HTTPException) as err:
        email_router.test_smtp_connection({'smtp_config': GOOD, 'password': ''}, user_id='u')
    assert err.value.status_code == 400


# ───────────────────────── the send loop ─────────────────────────

ACCOUNT = {'id': 'acct-1', 'from_email': 'me@example.com', 'from_name': 'Me', 'provider': 'resend',
           'daily_cap': 20, 'warmup_target': 100}
CAMPAIGN = {'id': 'camp-1', 'account_id': 'acct-1', 'status': 'sending', 'subject': 'Hi {{first_name}}',
            'body_html': '<p>Hello</p><a href="{{unsubscribe_url}}">unsubscribe</a>', 'email_accounts': ACCOUNT}


def _recipients(n):
    return [{'id': f'r{i}', 'email_contacts': {'email': f'p{i}@x.test', 'first_name': f'P{i}'}} for i in range(n)]


@pytest.fixture
def loop(monkeypatch):
    fake = FakeDB({'email_campaigns': [CAMPAIGN], 'email_campaign_variants': [], 'email_suppressions': [],
                   'email_campaign_recipients': _recipients(3)})
    monkeypatch.setattr(email_router, 'supabase', fake)
    monkeypatch.setattr(email_router, 'within_business_hours', lambda a: True)
    monkeypatch.setattr(email_router, 'todays_allowed_volume', lambda a: 100)
    monkeypatch.setattr(email_router, 'sent_today_count', lambda a: 0)
    monkeypatch.setattr(email_router, '_try_acquire_lock', lambda cid: True)
    monkeypatch.setattr(email_router, '_release_lock', lambda cid: None)
    monkeypatch.setattr(email_router, '_ensure_recipients_populated', lambda c: None)
    email_router._provider_backoff_until.clear()
    return fake


def _provider_that(monkeypatch, send):
    monkeypatch.setattr(email_router.sending, 'get_ready_provider',
                        lambda account: type('P', (), {'send': staticmethod(send)})())


def test_hitting_the_provider_limit_pauses_instead_of_failing(loop, monkeypatch):
    calls = []

    def send(*a):
        calls.append(a)
        raise providers.ProviderRateLimited('daily quota exceeded')
    _provider_that(monkeypatch, send)

    result = email_router._send_one_batch('camp-1')
    assert result['paused'] == 'provider_rate_limited' and result['failed'] == 0 and result['sent'] == 0
    assert len(calls) == 1  # stopped at the first refusal instead of hammering the provider
    assert all(u.get('status') != 'failed' for u in loop.updates('email_campaign_recipients'))


def test_a_paused_account_is_not_retried_until_the_backoff_passes(loop, monkeypatch):
    calls = []

    def send(*a):
        calls.append(a)
        raise providers.ProviderRateLimited('limit')
    _provider_that(monkeypatch, send)

    email_router._send_one_batch('camp-1')
    again = email_router._send_one_batch('camp-1')
    assert again['skipped'] == 'provider_rate_limited' and len(calls) == 1


def test_sending_resumes_after_the_backoff(loop, monkeypatch):
    _provider_that(monkeypatch, lambda *a: 'msg-id')
    email_router._provider_backoff_until['acct-1'] = datetime(2000, 1, 1, tzinfo=timezone.utc)
    result = email_router._send_one_batch('camp-1')
    assert result['sent'] == 3 and 'paused' not in result


def test_ordinary_failures_still_mark_the_recipient_failed(loop, monkeypatch):
    def send(*a):
        raise RuntimeError('550 5.1.1 user unknown')
    _provider_that(monkeypatch, send)
    result = email_router._send_one_batch('camp-1')
    assert result['failed'] == 3 and result['sent'] == 0 and 'paused' not in result
    assert [u for u in loop.updates('email_campaign_recipients') if u.get('status') == 'failed']


# ───────────────────────── the on/off switch ─────────────────────────

@pytest.mark.parametrize('value,expected', [
    ('true', True), ('TRUE', True), ('1', True), ('yes', True), ('on', True), (' true ',  True),
    ('', False), ('false', False), ('0', False), ('no', False), ('maybe', False),
])
def test_smtp_switch_values(monkeypatch, value, expected):
    monkeypatch.setenv('EMAIL_SMTP_ENABLED', value)
    assert providers.smtp_enabled() is expected


def test_smtp_is_off_when_the_variable_is_not_set():
    assert providers.smtp_enabled() is False


def test_the_providers_endpoint_reports_the_switch(monkeypatch):
    assert email_router.available_providers(user_id='u') == {'resend': True, 'smtp': False}
    monkeypatch.setenv('EMAIL_SMTP_ENABLED', 'true')
    assert email_router.available_providers(user_id='u') == {'resend': True, 'smtp': True}


def test_creating_an_smtp_account_is_refused_while_off_and_saves_nothing(db, monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_IP)
    with pytest.raises(HTTPException) as err:
        _create({**BASE, 'provider': 'smtp', 'smtp_config': GOOD})
    assert err.value.status_code == 400 and "isn't switched on" in err.value.detail
    assert db.inserted('email_accounts') == []


def test_the_connection_test_is_refused_while_off(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_IP)
    called = []
    monkeypatch.setattr(providers.SmtpProvider, 'check_connection', lambda self: called.append(1))
    with pytest.raises(HTTPException) as err:
        email_router.test_smtp_connection({'smtp_config': GOOD, 'password': 'pw'}, user_id='u')
    assert err.value.status_code == 400 and called == []  # never even tried to connect


def test_resend_accounts_are_unaffected_by_the_switch(db):
    _create({**BASE})  # SMTP switch is off (autouse fixture); Resend must still work
    assert db.inserted('email_accounts')[0]['provider'] == 'resend'


def test_an_unreachable_mail_server_gives_a_clear_400_from_the_test_endpoint(monkeypatch, smtp_on):
    _resolve_to(monkeypatch, PUBLIC_IP)

    def blocked(self):
        raise providers.ProviderUnavailable('Could not reach smtp.example.com:587. use port 2525')
    monkeypatch.setattr(providers.SmtpProvider, 'check_connection', blocked)
    with pytest.raises(HTTPException) as err:
        email_router.test_smtp_connection({'smtp_config': GOOD, 'password': 'pw'}, user_id='u')
    assert err.value.status_code == 400 and 'Could not reach' in err.value.detail


def test_an_unreachable_provider_pauses_the_campaign_and_keeps_recipients_pending(loop, monkeypatch):
    calls = []

    def send(*a):
        calls.append(a)
        raise providers.ProviderUnavailable('Could not reach smtp.example.com:587')
    _provider_that(monkeypatch, send)

    result = email_router._send_one_batch('camp-1')
    assert result['paused'] == 'provider_rate_limited' and result['failed'] == 0 and result['sent'] == 0
    assert len(calls) == 1
    assert all(u.get('status') != 'failed' for u in loop.updates('email_campaign_recipients'))
    assert email_router._send_one_batch('camp-1')['skipped'] == 'provider_rate_limited'  # and does not retry at once

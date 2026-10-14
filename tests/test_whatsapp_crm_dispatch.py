"""
tests/test_whatsapp_crm_dispatch.py: sending the WhatsApp messages the CRM pipeline queued
(raptor/whatsapp/router.py, _dispatch_crm_whatsapp; the database rules that decide WHETHER to queue are tested
against a real Postgres, see db/migrations/2026-10-14_crm_whatsapp.sql).

No network and no database: Supabase is replaced by a small in-memory fake that really filters, and Meta's API by a fake provider.
"""
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet

os.environ.setdefault('WHATSAPP_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('CONTENT_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.whatsapp import router as wa  # noqa: E402


class Result:
    def __init__(self, data, count=None):
        self.data, self.count = data, count


class Query:
    def __init__(self, db, name):
        self.db, self.name, self.op, self.payload = db, name, 'select', None
        self.filters, self._order, self._limit, self._count = [], None, None, False

    def select(self, *a, **k):
        self.op, self._count = 'select', k.get('count') == 'exact'
        return self

    def update(self, payload):
        self.op, self.payload = 'update', payload
        return self

    def insert(self, payload):
        self.op, self.payload = 'insert', payload
        return self

    def eq(self, col, val):
        self.filters.append(lambda r: r.get(col) == val)
        return self

    def lt(self, col, val):
        self.filters.append(lambda r: r.get(col) is not None and r[col] < val)
        return self

    def order(self, col, **k):
        self._order = col
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        rows = self.db.tables.setdefault(self.name, [])
        if self.op == 'insert':
            row = {'id': f'{self.name}-{len(rows) + 1}', **self.payload}
            rows.append(row)
            self.db.log.append((self.name, 'insert', dict(row)))
            return Result([row])
        hits = [r for r in rows if all(f(r) for f in self.filters)]
        if self._order:
            hits.sort(key=lambda r: r.get(self._order) or '')
        if self.op == 'update':
            for r in hits:
                r.update(self.payload)
            self.db.log.append((self.name, 'update', dict(self.payload)))
            return Result([dict(r) for r in hits])
        total = len(hits)
        if self._limit is not None:
            hits = hits[:self._limit]
        return Result([dict(r) for r in hits], total if self._count else None)


class FakeDB:
    def __init__(self, **tables):
        self.tables, self.log = {k: list(v) for k, v in tables.items()}, []

    def table(self, name):
        return Query(self, name)

    def row(self, deal_id):
        return next(r for r in self.tables['deal_whatsapp'] if r['deal_id'] == deal_id)


NOW = datetime(2026, 10, 14, 5, 0, tzinfo=timezone.utc)       # 10:30 in Asia/Kolkata: inside 9-18
NIGHT = datetime(2026, 10, 14, 20, 0, tzinfo=timezone.utc)    # 01:30 in Asia/Kolkata: outside
ACCOUNT = {'id': 'acct-1', 'owner_id': 'u1', 'phone_number_id': 'pn', 'encrypted_access_token': 'x', 'timezone': 'Asia/Kolkata',
           'business_hours_start': 9, 'business_hours_end': 18, 'daily_cap': 10, 'warmup_target': 20,
           'warmup_started_at': '2026-10-01T00:00:00+00:00'}


def pending(deal_id='d1', phone='919876543210', owner='org-1', created='2026-10-14T04:00:00+00:00', **over):
    return {'deal_id': deal_id, 'owner_id': owner, 'contact_id': 'c-' + deal_id, 'account_id': 'acct-1', 'status': 'pending',
            'to_phone': phone, 'template_name': 'intro_offer', 'template_language': 'en_US', 'params': ['Priya', 'Acme'],
            'message_id': None, 'error': None, 'attempts': 0, 'created_at': created, 'updated_at': created, **over}


class FakeProvider:
    def __init__(self, fail=None):
        self.sent, self.fail = [], fail

    def send_template(self, to, template, language, params):
        if self.fail:
            raise self.fail
        self.sent.append((to, template, language, params))
        return f'wamid.{len(self.sent)}'


@pytest.fixture
def env(monkeypatch):
    db = FakeDB(deal_whatsapp=[pending()], whatsapp_accounts=[ACCOUNT], whatsapp_suppressions=[], whatsapp_events=[])
    monkeypatch.setattr(wa, 'supabase', db)
    touched, logged = [], []
    monkeypatch.setattr(wa, '_touch_conversation', lambda *a, **k: (touched.append(a), 'conv-1')[1])
    monkeypatch.setattr(wa, '_log_interaction', lambda *a, **k: logged.append(a))
    monkeypatch.setattr(wa, '_already_sent_today', lambda account_id: 0)
    db.touched, db.logged = touched, logged
    return db


def run(db, provider=None, now=NOW, owner='org-1'):
    provider = provider or FakeProvider()
    return wa._dispatch_crm_whatsapp(owner, provider_for=lambda account: provider, now=now), provider


def http_error(status, body):
    request = httpx.Request('POST', 'https://graph.facebook.com/x')
    return httpx.HTTPStatusError('boom', request=request, response=httpx.Response(status, json=body, request=request))


def test_a_pending_message_is_sent_with_its_template_and_variables(env):
    result, provider = run(env)
    assert result == {'sent': 1, 'failed': 0, 'waiting': 0, 'skipped': 0, 'pending_left': 0}
    assert provider.sent == [('919876543210', 'intro_offer', 'en_US', ['Priya', 'Acme'])]
    row = env.row('d1')
    assert row['status'] == 'sent' and row['message_id'] == 'wamid.1' and row['sent_at'] and row['error'] is None


def test_it_shows_up_in_the_whatsapp_inbox_and_on_the_contact(env):
    run(env)
    assert env.touched[0][:3] == ('acct-1', '919876543210', 'outbound') and env.touched[0][4] == 'c-d1'
    assert [e for e in env.tables['whatsapp_events'] if e['event_type'] == 'sent' and e['provider_message_id'] == 'wamid.1']
    assert env.logged[0][0] == 'c-d1' and env.logged[0][1] == 'outbound'


def test_a_sent_message_is_never_sent_twice(env):
    run(env)
    result, provider = run(env)
    assert provider.sent == [] and result['sent'] == 0


def test_outside_business_hours_it_waits_and_says_why(env):
    result, provider = run(env, now=NIGHT)
    assert provider.sent == [] and result['waiting'] == 1 and result['pending_left'] == 1
    row = env.row('d1')
    assert row['status'] == 'pending' and 'business hours' in row['error'] and 'Asia/Kolkata' in row['error']
    result, provider = run(env, now=NOW)                      # and goes out once the hours begin
    assert result['sent'] == 1 and env.row('d1')['error'] is None


def test_hours_are_judged_on_the_accounts_own_clock_not_utc(env):
    # 04:00 UTC is 09:30 in India (inside 9-18) but would be outside if the UTC hour were compared.
    result, provider = run(env, now=datetime(2026, 10, 14, 4, 0, tzinfo=timezone.utc))
    assert result['sent'] == 1


def test_the_daily_limit_holds_it_back_until_tomorrow(env, monkeypatch):
    monkeypatch.setattr(wa, '_already_sent_today', lambda account_id: 999)
    result, provider = run(env)
    assert provider.sent == [] and result['waiting'] == 1
    assert env.row('d1')['status'] == 'pending' and 'limit' in env.row('d1')['error']


def test_the_limit_counts_messages_sent_in_the_same_run(env, monkeypatch):
    env.tables['deal_whatsapp'] = [pending(f'd{i}', f'91900000000{i}') for i in range(5)]
    monkeypatch.setattr(wa, 'todays_allowed_volume', lambda account: 3)
    result, provider = run(env)
    assert result['sent'] == 3 and result['waiting'] == 2


def test_someone_who_opted_out_since_it_was_queued_is_not_messaged(env):
    env.tables['whatsapp_suppressions'].append({'account_id': 'acct-1', 'phone': '919876543210'})
    result, provider = run(env)
    assert provider.sent == [] and result['skipped'] == 1
    assert env.row('d1')['status'] == 'skipped' and 'opted out' in env.row('d1')['error']


def test_metas_own_reason_is_shown_when_it_refuses(env):
    err = http_error(400, {'error': {'message': 'Recipient phone number not in allowed list', 'code': 131030}})
    result, provider = run(env, FakeProvider(fail=err))
    assert result['failed'] == 1
    row = env.row('d1')
    assert row['status'] == 'failed' and row['error'] == '(#131030) Recipient phone number not in allowed list'


def test_a_refusal_with_no_explanation_still_says_what_happened(env):
    err = http_error(401, {})
    run(env, FakeProvider(fail=err))
    assert 'HTTP 401' in env.row('d1')['error']


def test_a_temporary_problem_is_retried_not_failed(env):
    result, _ = run(env, FakeProvider(fail=http_error(503, {})))
    row = env.row('d1')
    assert result['waiting'] == 1 and row['status'] == 'pending' and row['attempts'] == 1 and 'again' in row['error']
    result, provider = run(env)                                # next time it works
    assert result['sent'] == 1 and env.row('d1')['status'] == 'sent'


def test_a_network_error_is_also_temporary(env):
    run(env, FakeProvider(fail=httpx.ConnectTimeout('slow')))
    assert env.row('d1')['status'] == 'pending'


def test_after_too_many_temporary_failures_it_gives_up(env):
    env.tables['deal_whatsapp'][0]['attempts'] = wa.CRM_MAX_ATTEMPTS - 1
    result, _ = run(env, FakeProvider(fail=http_error(500, {'error': {'message': 'Meta is down', 'code': 1}})))
    assert result['failed'] == 1 and env.row('d1')['status'] == 'failed'


def test_a_message_stuck_mid_send_is_marked_unknown_and_never_resent(env):
    env.tables['deal_whatsapp'] = [pending(status='sending', updated_at=(NOW - timedelta(minutes=30)).isoformat())]
    result, provider = run(env)
    row = env.row('d1')
    assert provider.sent == [] and row['status'] == 'failed' and 'unknown' in row['error']


def test_a_message_being_sent_right_now_is_left_alone(env):
    env.tables['deal_whatsapp'] = [pending(status='sending', updated_at=NOW.isoformat())]
    result, provider = run(env)
    assert provider.sent == [] and env.row('d1')['status'] == 'sending'


def test_a_claim_lost_to_another_tab_sends_nothing(env, monkeypatch):
    original = env.table

    def racing(name):
        q = original(name)
        if name == 'deal_whatsapp':
            run_exec = q.execute

            def execute():
                if q.op == 'update' and q.payload.get('status') == 'sending':
                    env.tables['deal_whatsapp'][0]['status'] = 'sending'   # someone else claimed it first
                return run_exec()
            q.execute = execute
        return q
    monkeypatch.setattr(env, 'table', racing)
    result, provider = run(env)
    assert provider.sent == [] and result['sent'] == 0


def test_only_this_organizations_messages_are_touched(env):
    env.tables['deal_whatsapp'].append(pending('theirs', owner='org-2'))
    result, provider = run(env, owner='org-1')
    assert [p[0] for p in provider.sent] == ['919876543210'] and env.row('theirs')['status'] == 'pending'


def test_a_removed_whatsapp_number_fails_the_message_clearly(env):
    env.tables['whatsapp_accounts'] = []
    result, provider = run(env)
    assert provider.sent == [] and env.row('d1')['status'] == 'failed' and 'no longer connected' in env.row('d1')['error']


def test_a_batch_is_five_at_a_time_and_reports_what_is_left(env):
    env.tables['deal_whatsapp'] = [pending(f'd{i}', f'9190000000{i:02d}', created=f'2026-10-14T04:{i:02d}:00+00:00') for i in range(7)]
    result, provider = run(env)
    assert result['sent'] == wa.CRM_BATCH_SIZE == 5 and result['pending_left'] == 2
    assert [p[0] for p in provider.sent] == [f'9190000000{i:02d}' for i in range(5)]      # oldest first


def test_logging_trouble_never_undoes_a_sent_message(env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('inbox table is down')
    monkeypatch.setattr(wa, '_touch_conversation', boom)
    result, provider = run(env)
    assert result['sent'] == 1 and env.row('d1')['status'] == 'sent'

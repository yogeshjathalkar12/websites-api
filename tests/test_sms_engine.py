"""
tests/test_sms_engine.py: targeted SMS (raptor/sms/engine.py + router.py): sending rules, STOP/START, replies, auto-replies,
sequences, the pipeline's queued texts, and Twilio's signed webhooks. The database rules that decide WHETHER the pipeline queues a text
are tested against a real Postgres (db/migrations/2026-10-21_sms.sql).

No network and no database: Supabase is replaced by a small in-memory fake that really filters, Twilio by a recorder.
"""
import base64
import hashlib
import hmac
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('WHATSAPP_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
os.environ.setdefault('CONTENT_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.sms import engine, router as sms_router  # noqa: E402

ORG = 'org-1'
CONN_ID = 'c' * 24
PUBLIC = 'https://api.example.test'
TOKEN = 'tokentokentokentoken'
SECRET = '{"account_sid": "AC%s", "auth_token": "%s"}' % ('a' * 32, TOKEN)
INSIDE = datetime(2026, 10, 21, 6, 0, tzinfo=timezone.utc)      # 11:30 in India
OUTSIDE = datetime(2026, 10, 21, 18, 0, tzinfo=timezone.utc)    # 23:30 in India


# ───────────────────────── fakes ─────────────────────────

class Result:
    def __init__(self, data, count=None):
        self.data, self.count = data, count


class Query:
    def __init__(self, db, name):
        self.db, self.name, self.op, self.payload = db, name, 'select', None
        self.filters, self._order, self._limit, self._count, self._on_conflict = [], None, None, False, None

    def select(self, *a, **k):
        self.op, self._count = 'select', k.get('count') == 'exact'
        return self

    def insert(self, payload):
        self.op, self.payload = 'insert', payload
        return self

    def update(self, payload):
        self.op, self.payload = 'update', payload
        return self

    def delete(self):
        self.op = 'delete'
        return self

    def upsert(self, payload, on_conflict=None):
        self.op, self.payload, self._on_conflict = 'upsert', payload, on_conflict
        return self

    def eq(self, col, val):
        self.filters.append(lambda r: r.get(col) == val)
        return self

    def neq(self, col, val):
        self.filters.append(lambda r: r.get(col) != val)
        return self

    def lt(self, col, val):
        self.filters.append(lambda r: r.get(col) is not None and str(r[col]) < str(val))
        return self

    def lte(self, col, val):
        self.filters.append(lambda r: r.get(col) is not None and str(r[col]) <= str(val))
        return self

    def gte(self, col, val):
        self.filters.append(lambda r: r.get(col) is not None and str(r[col]) >= str(val))
        return self

    def order(self, col, **k):
        self._order = (col, k.get('desc', False))
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        rows = self.db.tables.setdefault(self.name, [])
        if self.op == 'insert':
            row = {'id': f'{self.name}-{len(rows) + 1}-{uuid.uuid4().hex[:6]}', **self.payload}
            rows.append(row)
            return Result([dict(row)])
        if self.op == 'upsert':
            keys = (self._on_conflict or 'id').split(',')
            hit = next((r for r in rows if all(r.get(k) == self.payload.get(k) for k in keys)), None)
            if hit:
                hit.update(self.payload)
            else:
                rows.append({'id': f'{self.name}-{len(rows) + 1}', **self.payload})
            return Result([self.payload])
        hits = [r for r in rows if all(f(r) for f in self.filters)]
        if self.op == 'update':
            for r in hits:
                r.update(self.payload)
            return Result([dict(r) for r in hits])
        if self.op == 'delete':
            for r in hits:
                rows.remove(r)
            return Result([dict(r) for r in hits])
        if self._order:
            hits.sort(key=lambda r: str(r.get(self._order[0]) or ''), reverse=self._order[1])
        total = len(hits)
        if self._limit is not None:
            hits = hits[:self._limit]
        return Result([dict(r) for r in hits], total if self._count else None)


class FakeDB:
    def __init__(self, **tables):
        self.tables = {k: [dict(r) for r in v] for k, v in tables.items()}
        self.contacts_by_phone = {}

    def table(self, name):
        return Query(self, name)

    def rpc(self, name, args):
        assert name == 'sms_find_contact'
        found = self.contacts_by_phone.get(args['p_phone'])
        return type('R', (), {'execute': lambda self_: Result(found)})()

    def rows(self, name, **where):
        return [r for r in self.tables.get(name, []) if all(r.get(k) == v for k, v in where.items())]


class Twilio:
    """Records what would be sent and answers like Twilio. Set `fail` to (http status, json body) to make the next sends fail."""

    def __init__(self):
        self.sent, self.fail, self.n = [], None, 0
        self.gets, self.posts = [], []

    def post(self, url, auth=None, data=None, timeout=None, **kw):
        if 'Messages.json' in url:
            if self.fail:
                return _Resp(*self.fail)
            self.n += 1
            self.sent.append(dict(data))
            return _Resp(201, {'sid': f'SM{self.n}', 'status': 'queued'})
        self.posts.append((url, data))
        return _Resp(200, {})

    def get(self, url, auth=None, params=None, timeout=None, **kw):
        self.gets.append((url, params))
        return _Resp(200, {'incoming_phone_numbers': [{'sid': 'PN1'}]})


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


@pytest.fixture
def twilio(monkeypatch):
    t = Twilio()
    monkeypatch.setattr(engine.httpx, 'post', t.post)
    monkeypatch.setattr(engine.httpx, 'get', t.get)
    return t


def connection(**over):
    return {'id': CONN_ID, 'owner_id': ORG, 'provider': 'sms_twilio', 'status': 'connected', 'config': {'from_number': '+14155550100'}, **over}


def make_db(**tables):
    base = {'connections': [connection()], 'sms_settings': [{'owner_id': ORG, 'mode': 'semi', 'connection_id': CONN_ID, 'opt_in_confirmed_at': 'x',
                                                             'daily_limit': 100, 'send_from_hour': 9, 'send_until_hour': 21, 'timezone': 'Asia/Kolkata',
                                                             'country_code': '91', 'autoreply_enabled': True}]}
    base.update(tables)
    return FakeDB(**base)


def settings(db):
    return engine.settings_for(db, ORG)


def send(db, phone='+919876543210', body='Hello', now=INSIDE, **kw):
    return engine.send_text(db, org_id=ORG, connection=connection(), secret=SECRET, phone=phone, body=body, source=kw.pop('source', 'manual'),
                            settings=settings(db), public_api=PUBLIC, now=now, **kw)


SECRET_OF = lambda _id: SECRET  # noqa: E731


# ───────────────────────── small rules ─────────────────────────

@pytest.mark.parametrize('raw,cc,want', [('+91 98765 43210', '91', '+919876543210'), ('9876543210', '91', '+919876543210'), ('098765 43210', '91', '+919876543210'),
                                          ('0044 7700 900123', '91', '+447700900123'), ('(415) 555-0132', '1', '+14155550132'), ('12345', '91', None),
                                          ('', '91', None), ('call me', '91', None), (None, '91', None)])
def test_phone_numbers_become_international_the_same_way_as_in_the_database(raw, cc, want):
    assert engine.to_e164(raw, cc) == want


def test_tags_are_filled_and_unknown_tags_disappear():
    assert engine.render('Hi {{first_name}}, about {{company}} {{nothing}}.', {'first_name': 'Priya', 'company': 'Acme'}) == 'Hi Priya, about Acme .'


def test_contact_variables_fall_back_to_sensible_words():
    assert engine.contact_variables({'name': 'Anna Lee'}, '', '') == {'first_name': 'Anna', 'last_name': '', 'name': 'Anna Lee', 'company': 'your company', 'deal_title': ''}
    assert engine.contact_variables({}, 'Acme', 'Pilot')['first_name'] == 'there'


def test_sequence_steps_are_validated():
    assert engine.validate_steps([{'delay_hours': '24', 'text': ' Hi '}]) == [{'delay_hours': 24.0, 'text': 'Hi'}]
    for bad in ([], 'x', [{'delay_hours': 1, 'text': 'x'}] * 7, [{'delay_hours': 1, 'text': ''}], [{'delay_hours': -1, 'text': 'x'}],
                [{'delay_hours': 'soon', 'text': 'x'}], [{'delay_hours': 1, 'text': 'x' * 481}], [{'delay_hours': 1000, 'text': 'x'}]):
        with pytest.raises(ValueError):
            engine.validate_steps(bad)


def test_twilio_signatures_are_checked_with_the_connections_own_token():
    url, params = engine.inbound_url(PUBLIC, CONN_ID), {'From': '+919876543210', 'Body': 'Hi', 'MessageSid': 'SMx'}
    good = base64.b64encode(hmac.new(TOKEN.encode(), (url + ''.join(k + params[k] for k in sorted(params))).encode(), hashlib.sha1).digest()).decode()
    assert engine.valid_signature(TOKEN, url, params, good)
    assert not engine.valid_signature(TOKEN, url, {**params, 'Body': 'Hello'}, good)
    assert not engine.valid_signature('another-token-another-token', url, params, good)
    assert not engine.valid_signature(TOKEN, url, params, '') and not engine.valid_signature('', url, params, good)


# ───────────────────────── sending ─────────────────────────

def test_a_text_is_sent_from_the_customers_number_stored_logged_and_shown_on_the_contact(twilio):
    db = make_db()
    db.contacts_by_phone['+919876543210'] = 'contact-1'
    signals = []
    row = send(db, body='  Hello Priya  ', record=signals.append)
    assert twilio.sent == [{'To': '+919876543210', 'From': '+14155550100', 'Body': 'Hello Priya',
                            'StatusCallback': f'{PUBLIC}/api/raptor/sms/hook/{CONN_ID}/status'}]
    stored = db.rows('sms_messages')[0]
    assert stored['status'] == 'sent' and stored['provider_sid'] == 'SM1' and stored['direction'] == 'out' and stored['contact_id'] == 'contact-1'
    assert row['provider_sid'] == 'SM1'
    assert signals[0].name == 'sms_sent' and signals[0].entity['to'] == '+919876543210'
    note = db.rows('interactions')[0]
    assert note['type'] == 'sms' and note['direction'] == 'outbound' and note['contact_id'] == 'contact-1' and note['content'] == 'Hello Priya'


def test_empty_oversized_and_opted_out_messages_are_refused_before_anything_is_sent(twilio):
    db = make_db(sms_optouts=[{'owner_id': ORG, 'phone': '+919000000001'}])
    for body, text in (('  ', 'Write the message'), ('x' * 601, '600')):
        with pytest.raises(engine.SendError) as err:
            send(db, body=body)
        assert text in str(err.value)
    with pytest.raises(engine.SendError) as err:
        send(db, phone='+919000000001')
    assert err.value.code == 'opted_out'
    assert twilio.sent == [] and db.rows('sms_messages') == []


def test_nothing_goes_out_of_hours_but_a_reply_to_a_person_who_wrote_can(twilio):
    db = make_db()
    with pytest.raises(engine.Wait) as err:
        send(db, now=OUTSIDE)
    assert '09:00 to 21:00' in str(err.value) and twilio.sent == []
    send(db, now=OUTSIDE, check_hours=False)
    assert len(twilio.sent) == 1


def test_the_daily_limit_counts_what_went_out_today_and_not_failures(twilio):
    db = make_db()
    db.tables['sms_settings'][0]['daily_limit'] = 2
    send(db)
    twilio.fail = (400, {'code': 21211})
    with pytest.raises(engine.SendError):
        send(db)
    twilio.fail = None
    send(db)
    with pytest.raises(engine.Wait) as err:
        send(db)
    assert 'limit' in str(err.value) and len(twilio.sent) == 2
    tomorrow = INSIDE + timedelta(days=1)
    send(db, now=tomorrow)
    assert len(twilio.sent) == 3


def test_twilio_refusals_are_explained_in_plain_words_and_recorded(twilio):
    db = make_db()
    twilio.fail = (400, {'code': 21608, 'message': 'trial'})
    signals = []
    with pytest.raises(engine.SendError) as err:
        send(db, record=signals.append)
    assert 'trial' in str(err.value) and not err.value.temporary
    assert db.rows('sms_messages')[0]['status'] == 'failed' and 'trial' in db.rows('sms_messages')[0]['error']
    assert signals[0].name == 'sms_failed'
    twilio.fail = (503, {})
    with pytest.raises(engine.SendError) as err:
        send(db)
    assert err.value.temporary


# ───────────────────────── what Twilio tells us ─────────────────────────

def test_delivery_reports_move_forward_only():
    db = make_db(sms_messages=[{'id': 'm1', 'owner_id': ORG, 'connection_id': CONN_ID, 'provider_sid': 'SM1', 'status': 'sent', 'direction': 'out'}])
    conn = connection()
    assert engine.ingest_status(db, conn, {'MessageSid': 'SM1', 'MessageStatus': 'delivered'})['updated'] == 1
    assert engine.ingest_status(db, conn, {'MessageSid': 'SM1', 'MessageStatus': 'sent'})['updated'] == 0
    assert db.rows('sms_messages')[0]['status'] == 'delivered'
    assert engine.ingest_status(db, conn, {'MessageSid': 'unknown', 'MessageStatus': 'delivered'})['updated'] == 0
    assert engine.ingest_status(db, conn, {'MessageSid': 'SM1', 'MessageStatus': 'weird'})['updated'] == 0


def test_an_undelivered_text_keeps_the_reason():
    db = make_db(sms_messages=[{'id': 'm1', 'owner_id': ORG, 'connection_id': CONN_ID, 'provider_sid': 'SM1', 'status': 'sent', 'direction': 'out'}])
    engine.ingest_status(db, connection(), {'MessageSid': 'SM1', 'MessageStatus': 'undelivered', 'ErrorCode': '30005'})
    row = db.rows('sms_messages')[0]
    assert row['status'] == 'undelivered' and 'does not exist' in row['error']


# ───────────────────────── incoming texts ─────────────────────────

def inbound(db, body, sid='SMin1', phone='+919876543210', now=INSIDE, twilio_=None, signals=None):
    return engine.ingest_inbound(db, connection(), SECRET, {'From': phone, 'Body': body, 'MessageSid': sid}, PUBLIC,
                                 record=(signals.append if signals is not None else None), now=now)


def test_an_incoming_text_is_stored_once_and_shown_on_the_contact(twilio):
    db = make_db()
    db.contacts_by_phone['+919876543210'] = 'contact-1'
    signals = []
    assert inbound(db, 'Yes, call me tomorrow', signals=signals)['action'] == 'stored'
    assert inbound(db, 'Yes, call me tomorrow')['action'] == 'duplicate'
    row = db.rows('sms_messages')[0]
    assert len(db.rows('sms_messages')) == 1 and row['direction'] == 'in' and row['status'] == 'received' and row['contact_id'] == 'contact-1'
    assert db.rows('interactions')[0]['direction'] == 'inbound' and signals[0].name == 'sms_received'


@pytest.mark.parametrize('word', ['STOP', 'stop', ' Stop. ', 'UNSUBSCRIBE', 'cancel', 'End', 'QUIT', 'stopall'])
def test_stop_in_any_form_ends_everything_for_that_number(twilio, word):
    db = make_db(sms_enrollments=[{'id': 'e1', 'owner_id': ORG, 'phone': '+919876543210', 'status': 'active', 'sequence_id': 's1'}],
                 deal_sms=[{'deal_id': 'd1', 'owner_id': ORG, 'to_phone': '+919876543210', 'status': 'pending'}])
    signals = []
    assert inbound(db, word, signals=signals)['action'] == 'optout'
    assert db.rows('sms_optouts')[0]['phone'] == '+919876543210'
    assert db.rows('sms_enrollments')[0]['status'] == 'stopped'
    assert db.rows('deal_sms')[0]['status'] == 'skipped'
    assert twilio.sent == [] and any(s.name == 'sms_optout' for s in signals)
    with pytest.raises(engine.SendError):
        send(db)


def test_start_lets_a_person_back_in_and_nothing_else_does(twilio):
    db = make_db(sms_optouts=[{'owner_id': ORG, 'phone': '+919876543210'}])
    assert inbound(db, 'yes please')['action'] == 'stored'
    assert db.rows('sms_optouts')
    assert inbound(db, 'START', sid='SMin2')['action'] == 'optin'
    assert db.rows('sms_optouts') == []
    send(db)
    assert len(twilio.sent) == 1


def test_a_reply_ends_the_sequence_unless_it_was_set_to_carry_on(twilio):
    db = make_db(sms_sequences=[{'id': 's1', 'stop_on_reply': True}, {'id': 's2', 'stop_on_reply': False}],
                 sms_enrollments=[{'id': 'e1', 'owner_id': ORG, 'phone': '+919876543210', 'status': 'active', 'sequence_id': 's1'},
                                  {'id': 'e2', 'owner_id': ORG, 'phone': '+919876543210', 'status': 'active', 'sequence_id': 's2'},
                                  {'id': 'e3', 'owner_id': ORG, 'phone': '+910000000000', 'status': 'active', 'sequence_id': 's1'}])
    inbound(db, 'sounds good')
    status = {r['id']: r['status'] for r in db.rows('sms_enrollments')}
    assert status == {'e1': 'replied', 'e2': 'active', 'e3': 'active'}


def test_a_keyword_gets_one_automatic_answer_and_the_same_number_cannot_trigger_a_loop(twilio):
    rules = [{'id': 'r1', 'owner_id': ORG, 'keyword': 'price', 'match_type': 'contains', 'reply_text': 'Plans start at Rs 999.', 'is_active': True},
             {'id': 'r2', 'owner_id': ORG, 'keyword': 'demo', 'match_type': 'exact', 'reply_text': 'Book here.', 'is_active': True},
             {'id': 'r3', 'owner_id': ORG, 'keyword': 'hours', 'match_type': 'contains', 'reply_text': 'x', 'is_active': False}]
    db = make_db(sms_autoreplies=rules)
    assert inbound(db, 'What is the PRICE?', sid='a1')['action'] == 'autoreplied'
    assert twilio.sent[0]['Body'] == 'Plans start at Rs 999.' and db.rows('sms_messages', source='autoreply')[0]['direction'] == 'out'
    again = inbound(db, 'price again', sid='a2', now=INSIDE + timedelta(minutes=2))
    assert again['action'] == 'stored' and len(twilio.sent) == 1                       # same number inside the gap: no second answer
    assert inbound(db, 'demo', sid='a3', now=INSIDE + timedelta(minutes=30))['action'] == 'autoreplied'
    assert inbound(db, 'a demo please', sid='a4', phone='+919111111111')['action'] == 'stored'      # "exact" does not match a longer sentence
    assert inbound(db, 'opening hours?', sid='a5', phone='+919222222222')['action'] == 'stored'    # an inactive rule never answers
    for n in range(4):
        inbound(db, 'price', sid=f'b{n}', phone='+919333333333', now=INSIDE + timedelta(hours=n))
    assert len([m for m in db.rows('sms_messages', source='autoreply') if m['phone'] == '+919333333333']) == 3      # three a day at most


def test_auto_replies_can_be_switched_off_and_never_go_to_an_opted_out_number(twilio):
    rules = [{'id': 'r1', 'owner_id': ORG, 'keyword': 'price', 'match_type': 'contains', 'reply_text': 'Rs 999', 'is_active': True}]
    db = make_db(sms_autoreplies=rules)
    db.tables['sms_settings'][0]['autoreply_enabled'] = False
    assert inbound(db, 'price?')['action'] == 'stored' and twilio.sent == []
    db.tables['sms_settings'][0]['autoreply_enabled'] = True
    db.tables['sms_optouts'] = [{'owner_id': ORG, 'phone': '+919876543210'}]
    assert inbound(db, 'price?', sid='z')['action'] == 'stored' and twilio.sent == []


def test_a_failing_auto_reply_never_loses_the_incoming_text(twilio):
    db = make_db(sms_autoreplies=[{'id': 'r1', 'owner_id': ORG, 'keyword': 'price', 'match_type': 'contains', 'reply_text': 'Rs 999', 'is_active': True}])
    twilio.fail = (400, {'code': 21608})
    out = inbound(db, 'price?')
    assert out['action'] == 'stored' and len(db.rows('sms_messages', direction='in')) == 1


# ───────────────────────── sequences ─────────────────────────

SEQ = {'id': 's1', 'owner_id': ORG, 'name': 'Follow up', 'is_active': True, 'stop_on_reply': True,
       'steps': [{'delay_hours': 24, 'text': 'Hi {{first_name}}, did you see my note?'}, {'delay_hours': 48, 'text': 'Last try, {{first_name}}.'}]}


def deals_db(**extra):
    return make_db(
        deals=[{'id': 'd1', 'owner_id': ORG, 'contact_id': 'k1', 'company_id': 'co1', 'title': 'Pilot'},
               {'id': 'd2', 'owner_id': ORG, 'contact_id': 'k2', 'title': 'No number'},
               {'id': 'd3', 'owner_id': ORG, 'contact_id': None, 'title': 'No contact'},
               {'id': 'd4', 'owner_id': ORG, 'contact_id': 'k4', 'title': 'Opted out'},
               {'id': 'dx', 'owner_id': 'other-org', 'contact_id': 'k1', 'title': 'Theirs'}],
        contacts=[{'id': 'k1', 'name': 'Priya Sharma', 'first_name': 'Priya', 'phone': '98765 43210'}, {'id': 'k2', 'name': 'Ravi', 'phone': 'n/a'},
                  {'id': 'k4', 'name': 'Opt', 'phone': '9000011111'}],
        companies=[{'id': 'co1', 'name': 'Acme'}], sms_sequences=[dict(SEQ)], sms_optouts=[{'owner_id': ORG, 'phone': '+919000011111'}], **extra)


def enroll(db, ids, now=INSIDE):
    return engine.enroll_deals(db, org_id=ORG, sequence=SEQ, deal_ids=ids, settings=settings(db), connection=connection(), user_id='u1', now=now)


def test_enrolling_picks_chosen_deals_and_explains_every_skip():
    db = deals_db()
    out = {r['deal_id']: r for r in enroll(db, ['d1', 'd2', 'd3', 'd4', 'dx', 'nope'])}
    assert out['d1']['result'] == 'enrolled'
    for skipped, text in (('d2', 'valid phone'), ('d3', 'valid phone'), ('d4', 'opted out'), ('dx', 'not found'), ('nope', 'not found')):
        assert out[skipped]['result'] == 'skipped' and text in out[skipped]['reason'], (skipped, out[skipped])
    row = db.rows('sms_enrollments')[0]
    assert row['phone'] == '+919876543210' and row['vars']['first_name'] == 'Priya' and row['vars']['company'] == 'Acme' and row['step'] == 0
    assert row['next_at'] == (INSIDE + timedelta(hours=24)).isoformat()
    assert enroll(db, ['d1'])[0]['reason'] == 'Already in this sequence.'


def test_enrolling_is_capped_so_it_can_never_become_a_blast():
    db = deals_db()
    with pytest.raises(ValueError) as err:
        enroll(db, [f'd{i}' for i in range(26)])
    assert '25' in str(err.value) and db.rows('sms_enrollments') == []


def advance(db, now, **kw):
    return engine.advance_enrollments(db, org_id=ORG, get_secret=SECRET_OF, public_api=PUBLIC, now=now, **kw)


def test_a_sequence_sends_each_step_when_due_waits_between_and_completes():
    db = deals_db()
    enroll(db, ['d1'])
    t = Twilio()
    import raptor.sms.engine as e
    e.httpx.post, e.httpx.get = t.post, t.get
    assert advance(db, INSIDE + timedelta(hours=23))['sent'] == 0                       # not due yet
    assert advance(db, INSIDE + timedelta(hours=25))['sent'] == 1
    assert t.sent[0]['Body'] == 'Hi Priya, did you see my note?'
    row = db.rows('sms_enrollments')[0]
    assert row['step'] == 1 and row['status'] == 'active' and row['next_at'] == (INSIDE + timedelta(hours=25 + 48)).isoformat()
    assert advance(db, INSIDE + timedelta(hours=26))['sent'] == 0
    assert advance(db, INSIDE + timedelta(hours=75))['sent'] == 1 and t.sent[1]['Body'] == 'Last try, Priya.'
    assert db.rows('sms_enrollments')[0]['status'] == 'completed'
    assert [m['source'] for m in db.rows('sms_messages')] == ['sequence', 'sequence'] and db.rows('sms_messages')[1]['step'] == 1


def test_a_due_step_waits_for_sending_hours_instead_of_going_out_at_night(twilio):
    db = deals_db()
    enroll(db, ['d1'])
    night = INSIDE + timedelta(hours=36)                  # 23:30 in India
    assert OUTSIDE.hour == 18
    night = OUTSIDE + timedelta(days=1)
    out = advance(db, night)
    assert out['sent'] == 0 and out['waiting'] == 1 and twilio.sent == []
    assert db.rows('sms_enrollments')[0]['next_at'] == (INSIDE + timedelta(hours=24)).isoformat()    # still due at the next pass
    assert advance(db, night + timedelta(hours=12))['sent'] == 1                                      # 11:30 next morning


def test_a_sequence_stops_for_someone_who_opted_out_or_when_switched_off(twilio):
    db = deals_db()
    enroll(db, ['d1'])
    db.tables['sms_optouts'].append({'owner_id': ORG, 'phone': '+919876543210'})
    out = advance(db, INSIDE + timedelta(hours=30))
    assert out['stopped'] == 1 and twilio.sent == [] and db.rows('sms_enrollments')[0]['status'] == 'stopped'
    db2 = deals_db()
    enroll(db2, ['d1'])
    db2.tables['sms_sequences'][0]['is_active'] = False
    assert advance(db2, INSIDE + timedelta(hours=30))['stopped'] == 1 and twilio.sent == []


def test_two_passes_at_the_same_moment_send_the_text_once(twilio):
    db = deals_db()
    enroll(db, ['d1'])
    due = INSIDE + timedelta(hours=30)
    first = advance(db, due)
    second = advance(db, due)
    assert first['sent'] == 1 and second['sent'] == 0 and len(twilio.sent) == 1


def test_a_refused_step_ends_the_run_but_a_temporary_problem_is_retried(twilio):
    db = deals_db()
    enroll(db, ['d1'])
    twilio.fail = (400, {'code': 21211})
    assert advance(db, INSIDE + timedelta(hours=30))['failed'] == 1
    row = db.rows('sms_enrollments')[0]
    assert row['status'] == 'failed' and 'valid phone' in row['stop_reason']
    db2 = deals_db()
    enroll(db2, ['d1'])
    twilio.fail = (503, {})
    out = advance(db2, INSIDE + timedelta(hours=30))
    assert out['failed'] == 0 and out['waiting'] == 1 and db2.rows('sms_enrollments')[0]['status'] == 'active'
    assert db2.rows('sms_enrollments')[0]['next_at'] > (INSIDE + timedelta(hours=30)).isoformat()    # tried again in 15 minutes


# ───────────────────────── the CRM pipeline ─────────────────────────

def pending(deal_id='d1', phone='+919876543210', **over):
    return {'deal_id': deal_id, 'owner_id': ORG, 'connection_id': CONN_ID, 'status': 'pending', 'to_phone': phone, 'body': 'Hi Priya, open to a chat?',
            'attempts': 0, 'contact_id': 'k1', 'created_at': '2026-10-21T01:00:00+00:00', 'updated_at': '2026-10-21T01:00:00+00:00', **over}


def dispatch(db, now=INSIDE):
    return engine.dispatch_crm(db, org_id=ORG, get_secret=SECRET_OF, public_api=PUBLIC, now=now)


def test_a_queued_first_text_goes_out_and_the_card_learns_its_id(twilio):
    db = make_db(deal_sms=[pending()])
    out = dispatch(db)
    assert out['sent'] == 1 and out['pending_left'] == 0
    row = db.rows('deal_sms')[0]
    assert row['status'] == 'sent' and row['message_id'] == 'SM1' and row['sent_at'] == INSIDE.isoformat()
    assert twilio.sent[0]['Body'] == 'Hi Priya, open to a chat?'
    assert db.rows('sms_messages')[0]['deal_id'] == 'd1' and db.rows('sms_messages')[0]['source'] == 'crm'


def test_queued_texts_wait_for_sending_hours_and_the_daily_limit(twilio):
    db = make_db(deal_sms=[pending()])
    out = dispatch(db, OUTSIDE)
    assert out['waiting'] == 1 and out['sent'] == 0 and 'sending hours' in db.rows('deal_sms')[0]['error'] and db.rows('deal_sms')[0]['status'] == 'pending'
    db.tables['sms_settings'][0]['daily_limit'] = 1
    db.tables['deal_sms'].append(pending('d2', '+919000000002'))
    out = dispatch(db)
    assert out['sent'] == 1 and out['waiting'] == 1 and 'limit' in db.rows('deal_sms', deal_id='d2')[0]['error']


def test_a_number_that_opted_out_after_queueing_is_skipped(twilio):
    db = make_db(deal_sms=[pending()], sms_optouts=[{'owner_id': ORG, 'phone': '+919876543210'}])
    out = dispatch(db)
    assert out['skipped'] == 1 and twilio.sent == [] and db.rows('deal_sms')[0]['status'] == 'skipped'


def test_a_text_stuck_in_sending_is_marked_unknown_and_never_sent_twice(twilio):
    db = make_db(deal_sms=[pending(status='sending', updated_at=(INSIDE - timedelta(minutes=30)).isoformat())])
    dispatch(db)
    row = db.rows('deal_sms')[0]
    assert row['status'] == 'failed' and 'unknown' in row['error'] and twilio.sent == []


def test_a_refused_text_fails_with_the_reason_and_a_temporary_problem_retries(twilio):
    db = make_db(deal_sms=[pending()])
    twilio.fail = (503, {})
    assert dispatch(db)['waiting'] == 1
    assert db.rows('deal_sms')[0]['status'] == 'pending' and db.rows('deal_sms')[0]['attempts'] == 1
    twilio.fail = (400, {'code': 21614})
    assert dispatch(db)['failed'] == 1
    assert db.rows('deal_sms')[0]['status'] == 'failed' and 'cannot receive' in db.rows('deal_sms')[0]['error']
    db2 = make_db(deal_sms=[pending(attempts=4)])
    twilio.fail = (503, {})
    assert dispatch(db2)['failed'] == 1                                # five tries is enough


def test_a_missing_or_paused_number_fails_the_text_instead_of_hanging(twilio):
    db = make_db(deal_sms=[pending()])
    db.tables['connections'][0]['status'] = 'paused'
    assert dispatch(db)['failed'] == 1 and twilio.sent == []


def test_after_the_first_text_the_contact_can_start_a_follow_up_sequence(twilio):
    db = deals_db(deal_sms=[pending()])
    db.tables['sms_settings'][0]['sequence_id'] = 's1'
    dispatch(db)
    enrolled = db.rows('sms_enrollments')
    assert len(enrolled) == 1 and enrolled[0]['deal_id'] == 'd1' and enrolled[0]['status'] == 'active'
    assert enrolled[0]['next_at'] == (INSIDE + timedelta(hours=24)).isoformat()


def test_a_follow_up_problem_never_undoes_the_text_that_went_out(twilio):
    db = make_db(deal_sms=[pending()])
    db.tables['sms_settings'][0]['sequence_id'] = 'missing'
    assert dispatch(db)['sent'] == 1 and db.rows('deal_sms')[0]['status'] == 'sent'


# ───────────────────────── the HTTP surface ─────────────────────────

def sign(url, params, token=TOKEN):
    return base64.b64encode(hmac.new(token.encode(), (url + ''.join(k + params[k] for k in sorted(params))).encode(), hashlib.sha1).digest()).decode()


@pytest.fixture
def api(monkeypatch, twilio):
    db = make_db(deals=[], contacts=[])
    monkeypatch.setattr(sms_router, '_db', lambda: db)
    monkeypatch.setattr(sms_router, '_secret', lambda connection_id: SECRET)
    monkeypatch.setattr(sms_router, '_public', lambda: PUBLIC)
    monkeypatch.setattr(sms_router, 'require_pro', lambda user_id, message='': None)
    monkeypatch.setattr(sms_router.conn, '_store_signals', lambda connection, signals: signals)
    monkeypatch.setattr(engine, 'now_utc', lambda: INSIDE)       # the router uses the real clock: pin it inside sending hours
    sms_router._buckets.clear()
    app = FastAPI()
    app.include_router(sms_router.router, prefix='/api/raptor/sms')
    app.dependency_overrides[sms_router.get_current_user] = lambda: ORG
    return TestClient(app), db


def hook(client, kind, params, token=TOKEN, connection_id=CONN_ID):
    url = (engine.inbound_url if kind == 'inbound' else engine.status_callback_url)(PUBLIC, CONN_ID)
    return client.post(f'/api/raptor/sms/hook/{connection_id}/{kind}', data=params, headers={'X-Twilio-Signature': sign(url, params, token)})


def test_twilio_webhooks_need_a_valid_signature_and_answer_with_empty_twiml(api):
    client, db = api
    params = {'From': '+919876543210', 'Body': 'Hello there', 'MessageSid': 'SMw1'}
    ok = hook(client, 'inbound', params)
    assert ok.status_code == 200 and '<Response></Response>' in ok.text and 'xml' in ok.headers['content-type']
    assert len(db.rows('sms_messages', direction='in')) == 1
    assert hook(client, 'inbound', {**params, 'MessageSid': 'SMw2'}, token='another-token-another-token').status_code == 403
    assert client.post(f'/api/raptor/sms/hook/{CONN_ID}/inbound', data=params).status_code == 403
    assert hook(client, 'inbound', params, connection_id='f' * 24).status_code == 404
    assert hook(client, 'inbound', params, connection_id='short').status_code == 404
    assert len(db.rows('sms_messages', direction='in')) == 1


def test_a_delivery_report_arrives_through_the_signed_status_webhook(api):
    client, db = api
    db.tables['sms_messages'] = [{'id': 'm1', 'owner_id': ORG, 'connection_id': CONN_ID, 'provider_sid': 'SM9', 'status': 'sent', 'direction': 'out'}]
    assert hook(client, 'status', {'MessageSid': 'SM9', 'MessageStatus': 'delivered'}).status_code == 204
    assert db.rows('sms_messages')[0]['status'] == 'delivered'


def test_the_webhook_is_rate_limited_per_connection(api, monkeypatch):
    client, db = api
    monkeypatch.setattr(sms_router, '_LIMIT', 2)
    codes = [hook(client, 'inbound', {'From': '+919876543210', 'Body': f'hi {n}', 'MessageSid': f'SMr{n}'}).status_code for n in range(4)]
    assert codes == [200, 200, 429, 429]


def test_sending_one_text_by_number_is_logged_and_refuses_bad_numbers(api, twilio):
    client, db = api
    ok = client.post('/api/raptor/sms/send', json={'phone': '+91 98765 43210', 'text': 'Hello', 'connection_id': CONN_ID})
    assert ok.status_code == 200 and ok.json()['message']['status'] == 'sent' and twilio.sent[0]['To'] == '+919876543210'
    bad = client.post('/api/raptor/sms/send', json={'phone': '98765', 'text': 'Hello'})
    assert bad.status_code == 422 and 'country code' in bad.json()['detail']
    db.tables['sms_optouts'] = [{'owner_id': ORG, 'phone': '+919876543210'}]
    refused = client.post('/api/raptor/sms/send', json={'phone': '+919876543210', 'text': 'Hello'})
    assert refused.status_code == 422 and 'opted out' in refused.json()['detail']


def test_sending_needs_a_connected_twilio_number(api):
    client, db = api
    db.tables['connections'] = []
    resp = client.post('/api/raptor/sms/send', json={'phone': '+919876543210', 'text': 'Hello'})
    assert resp.status_code == 404 and 'Connect your Twilio' in resp.json()['detail']


def test_a_first_text_obeys_the_hours_but_an_answer_to_someone_who_just_wrote_does_not(api, twilio, monkeypatch):
    client, db = api
    monkeypatch.setattr(engine, 'now_utc', lambda: OUTSIDE)
    cold = client.post('/api/raptor/sms/send', json={'phone': '+919876543210', 'text': 'Hello'})
    assert cold.status_code == 429 and 'sending hours' in cold.json()['detail'] and twilio.sent == []
    db.tables['sms_messages'].append({'id': 'in1', 'owner_id': ORG, 'phone': '+919876543210', 'direction': 'in', 'created_at': (OUTSIDE - timedelta(hours=1)).isoformat()})
    warm = client.post('/api/raptor/sms/send', json={'phone': '+919876543210', 'text': 'Thanks for writing'})
    assert warm.status_code == 200 and len(twilio.sent) == 1


def test_sequences_and_auto_replies_are_validated_and_scoped_to_the_organization(api):
    client, db = api
    ok = client.post('/api/raptor/sms/sequences', json={'name': 'Follow up', 'steps': [{'delay_hours': 24, 'text': 'Hi'}]})
    assert ok.status_code == 200
    sid = ok.json()['sequence']['id']
    assert client.post('/api/raptor/sms/sequences', json={'name': 'Bad', 'steps': []}).status_code == 422
    assert client.post('/api/raptor/sms/sequences', json={'name': '', 'steps': [{'delay_hours': 1, 'text': 'x'}]}).status_code == 422
    db.tables['sms_sequences'].append({'id': 'theirs', 'owner_id': 'other-org', 'steps': []})
    assert client.patch('/api/raptor/sms/sequences/theirs', json={'name': 'Mine now'}).status_code == 404
    assert client.delete('/api/raptor/sms/sequences/theirs').status_code == 404
    assert client.patch(f'/api/raptor/sms/sequences/{sid}', json={'is_active': False}).status_code == 200
    assert db.rows('sms_sequences', id=sid)[0]['is_active'] is False
    rule = client.post('/api/raptor/sms/autoreplies', json={'keyword': 'Price', 'reply_text': 'Rs 999'})
    assert rule.status_code == 200
    for bad in ({'keyword': 'STOP', 'reply_text': 'x'}, {'keyword': 'start', 'reply_text': 'x'}, {'keyword': 'a', 'reply_text': ''},
                {'keyword': 'a', 'reply_text': 'x', 'match_type': 'regex'}, {'keyword': 'x' * 61, 'reply_text': 'x'}):
        assert client.post('/api/raptor/sms/autoreplies', json=bad).status_code == 422, bad


def test_enrolling_through_the_api_needs_consent_and_a_chosen_short_list(api):
    client, db = api
    db.tables.update(deals=[{'id': 'd1', 'owner_id': ORG, 'contact_id': 'k1', 'title': 'Pilot'}], contacts=[{'id': 'k1', 'name': 'Priya', 'phone': '9876543210'}],
                     sms_sequences=[dict(SEQ)])
    db.tables['sms_settings'][0]['opt_in_confirmed_at'] = None
    assert client.post('/api/raptor/sms/sequences/s1/enroll', json={'deal_ids': ['d1']}).status_code == 409
    db.tables['sms_settings'][0]['opt_in_confirmed_at'] = 'x'
    assert client.post('/api/raptor/sms/sequences/s1/enroll', json={'deal_ids': [f'd{i}' for i in range(26)]}).status_code == 422
    ok = client.post('/api/raptor/sms/sequences/s1/enroll', json={'deal_ids': ['d1']})
    assert ok.status_code == 200 and ok.json()['enrolled'] == 1
    assert client.post('/api/raptor/sms/enrollments/' + db.rows('sms_enrollments')[0]['id'] + '/stop').status_code == 200
    assert db.rows('sms_enrollments')[0]['status'] == 'stopped'


def test_adding_an_opt_out_by_hand_stops_their_sequences_and_cannot_be_undone_here(api):
    client, db = api
    db.tables['sms_enrollments'] = [{'id': 'e1', 'owner_id': ORG, 'phone': '+919876543210', 'status': 'active', 'sequence_id': 's1'}]
    assert client.post('/api/raptor/sms/optouts', json={'phone': '+91 98765 43210'}).status_code == 200
    assert db.rows('sms_optouts')[0]['phone'] == '+919876543210' and db.rows('sms_enrollments')[0]['status'] == 'stopped'
    assert client.delete('/api/raptor/sms/optouts').status_code in (404, 405)


def test_the_cron_tick_needs_the_secret(api, monkeypatch):
    client, _ = api
    monkeypatch.setenv('AUTOMATION_CRON_SECRET', 'cron-secret-123')
    assert client.post('/api/raptor/sms/tick').status_code == 401
    assert client.post('/api/raptor/sms/tick', headers={'X-Automation-Secret': 'wrong'}).status_code == 401
    ok = client.post('/api/raptor/sms/tick', headers={'X-Automation-Secret': 'cron-secret-123'})
    assert ok.status_code == 200 and ok.json()['sent'] == 0


def test_webhook_setup_points_the_twilio_number_at_raptor_and_remembers_it(api, twilio):
    client, db = api
    info = client.get(f'/api/raptor/sms/webhook/{CONN_ID}').json()
    assert info == {'url': f'{PUBLIC}/api/raptor/sms/hook/{CONN_ID}/inbound', 'configured': False}
    done = client.post(f'/api/raptor/sms/webhook/{CONN_ID}/setup').json()
    assert done['configured'] is True
    assert twilio.posts[0][1] == {'SmsUrl': f'{PUBLIC}/api/raptor/sms/hook/{CONN_ID}/inbound', 'SmsMethod': 'POST'}
    assert db.tables['connections'][0]['config']['webhook_set'] is True

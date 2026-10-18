"""tests/test_whatsapp_send_now.py: "deliver this one WhatsApp message now" (raptor/whatsapp/router.py, send_message_now).
No network and no database: the same in-memory Supabase as the CRM dispatch tests, and a fake Meta."""
import pytest
from fastapi import HTTPException

from tests.test_whatsapp_crm_dispatch import ACCOUNT, FakeDB  # noqa: E402,I001  (sets the encryption keys the router needs before it is imported)
from raptor.whatsapp import router as wa  # noqa: E402


class Meta:
    def __init__(self, fail=None):
        self.sent, self.fail = [], fail

    def send_text(self, to, text):
        if self.fail:
            raise self.fail
        self.sent.append(('text', to, text))
        return 'wamid.text'

    def send_template(self, to, name, language, params):
        if self.fail:
            raise self.fail
        self.sent.append(('template', to, name, language, params))
        return 'wamid.tpl'


@pytest.fixture
def env(monkeypatch):
    db = FakeDB(whatsapp_accounts=[ACCOUNT, {**ACCOUNT, 'id': 'acct-2', 'owner_id': 'someone-else'}], whatsapp_suppressions=[{'id': 's1', 'account_id': 'acct-1', 'phone': '919800000009'}],
                whatsapp_events=[])
    meta = Meta()
    monkeypatch.setattr(wa, 'supabase', db)
    monkeypatch.setattr(wa, '_decrypted_provider', lambda account: meta)
    touched, logged = [], []
    monkeypatch.setattr(wa, '_crm_contact_id_for', lambda account_id, phone: 'crm-1')
    monkeypatch.setattr(wa, '_touch_conversation', lambda *a, **k: (touched.append((a, k)), 'conv-1')[1])
    monkeypatch.setattr(wa, '_log_interaction', lambda *a, **k: logged.append(a))
    wa._send_now_times.clear()
    db.meta, db.touched, db.logged = meta, touched, logged
    return db


def send(**body):
    return wa.send_message_now({'account_id': 'acct-1', 'phone': '+91 98765 43210', **body}, user_id='u1')


def test_a_text_is_sent_at_once_to_the_cleaned_number_and_recorded(env):
    out = send(text='  Hello, your order is ready.  ')
    assert out == {'ok': True, 'provider_message_id': 'wamid.text', 'mode': 'text'}
    assert env.meta.sent == [('text', '919876543210', 'Hello, your order is ready.')]
    event = env.tables['whatsapp_events'][0]
    assert event['body_text'] == 'Hello, your order is ready.' and event['direction'] == 'outbound' and event['contact_phone'] == '919876543210'
    assert env.touched[0][1] == {'agent_id': 'u1'} and env.logged == [('crm-1', 'outbound', 'Hello, your order is ready.')]


def test_an_approved_template_goes_out_with_its_variables_even_outside_the_24_hour_window(env):
    out = send(template={'name': 'order_ready', 'language': 'en_US', 'params': ['Priya', ' #4412 ']})
    assert out['mode'] == 'template' and out['provider_message_id'] == 'wamid.tpl'
    assert env.meta.sent == [('template', '919876543210', 'order_ready', 'en_US', ['Priya', '#4412'])]
    assert env.tables['whatsapp_events'][0]['body_text'] == '[Template: order_ready] Priya, #4412'


def test_what_is_wrong_is_said_in_plain_words_and_nothing_is_sent(env):
    cases = [({'phone': '12'}, 'country code'), ({'account_id': ''}, 'which WhatsApp number'), ({}, 'either a text message or an approved template'),
             ({'text': 'a', 'template': {'name': 'x'}}, 'either a text message or an approved template'), ({'text': 'x' * 5000}, '4096'),
             ({'template': {'name': 'Order Ready!', 'language': 'en_US'}}, "template's name"), ({'template': {'name': 'ok_name', 'language': 'english'}}, 'language'),
             ({'template': {'name': 'ok_name', 'language': 'en_US', 'params': ['a', '  ']}}, 'every variable')]
    for body, words in cases:
        with pytest.raises(HTTPException) as err:
            send(**body)
        assert err.value.status_code == 400 and words in err.value.detail, (body, err.value.detail)
    assert env.meta.sent == []


def test_only_the_owner_of_the_number_can_send_and_a_stranger_gets_nothing(env):
    with pytest.raises(HTTPException) as err:
        wa.send_message_now({'account_id': 'acct-2', 'phone': '919876543210', 'text': 'hi'}, user_id='u1')
    assert err.value.status_code == 403
    with pytest.raises(HTTPException) as err:
        wa.send_message_now({'account_id': 'nope', 'phone': '919876543210', 'text': 'hi'}, user_id='u1')
    assert err.value.status_code == 404
    assert env.meta.sent == []


def test_a_person_who_opted_out_is_never_messaged(env):
    with pytest.raises(HTTPException) as err:
        send(phone='919800000009', text='hi')
    assert err.value.status_code == 400 and 'opted out' in err.value.detail
    assert env.meta.sent == []


def test_meta_refusing_a_text_explains_the_24_hour_rule_and_a_template_the_checks_to_make(env):
    env.meta.fail = RuntimeError('(#131047) Re-engagement message')
    with pytest.raises(HTTPException) as err:
        send(text='hi')
    assert '24 hours' in err.value.detail and 'template' in err.value.detail
    with pytest.raises(HTTPException) as err:
        send(template={'name': 'order_ready', 'language': 'en_US', 'params': []})
    assert 'approved' in err.value.detail and 'language' in err.value.detail
    assert not env.tables['whatsapp_events']                                    # a message that was not sent is not recorded as sent


def test_a_runaway_sender_is_slowed_down(env, monkeypatch):
    monkeypatch.setattr(wa, 'SEND_NOW_LIMIT', 3)
    for _ in range(3):
        send(text='hi')
    with pytest.raises(HTTPException) as err:
        send(text='hi')
    assert err.value.status_code == 429 and len(env.meta.sent) == 3

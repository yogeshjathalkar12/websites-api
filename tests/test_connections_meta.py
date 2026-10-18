"""tests/test_connections_meta.py - Facebook Pages, Lead Ads and Instagram: the switch, the sign-in that makes three kinds of connection, the
signed webhook, messages / comments / leads, replies inside Meta's 24-hour window, and Meta's data-deletion callbacks.

No network and no database: a fake Graph API answers by path, and the same in-memory Supabase as test_connections.py holds the data."""
import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.connections import alerts, hooks, meta, vault  # noqa: E402
from raptor.connections import router as conn_router  # noqa: E402
from raptor.connections.registry import ConnectorError  # noqa: E402
from tests.test_connections import FakeResponse, world  # noqa: E402,F401
from tests.test_connections_channels import signals_named, web  # noqa: E402,F401

GRAPH = 'https://graph.facebook.com/v23.0/'
SECRET = 'app-secret-xyz'


def now_ms(hours_ago=0):
    return int((datetime.now(timezone.utc) - timedelta(hours=hours_ago)).timestamp() * 1000)


@pytest.fixture
def graph(world, web, monkeypatch):
    for key, value in (('META_CHANNELS_ENABLED', 'true'), ('META_APP_ID', 'app-1'), ('META_APP_SECRET', SECRET),
                       ('META_WEBHOOK_VERIFY_TOKEN', 'verify-me'), ('WEB_APP_URL', 'https://app.test/ventures/raptor/app/')):
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('META_ALLOWED_ORGS', raising=False)
    state = {'perms': {p: 'granted' for p in meta.SCOPES}, 'pages': [
        {'id': 'p1', 'name': 'Acme Page', 'access_token': 'PAGE-TOKEN-1', 'instagram_business_account': {'id': 'ig1', 'username': 'acme'}},
        {'id': 'p2', 'name': 'Acme Labs', 'access_token': 'PAGE-TOKEN-2'}],
        'send_error': None, 'lead_error': None, 'subscribed': []}

    def answer(url, params=None, json=None, **kw):
        path = url[len(GRAPH):]
        params = params or {}
        if path == 'oauth/access_token':
            return {'access_token': 'long-user' if 'fb_exchange_token' in params else 'short-user'}
        if path == 'me/permissions':
            return {'data': [{'permission': k, 'status': v} for k, v in state['perms'].items()]}
        if path == 'me':
            return {'id': 'fb-user-1', 'name': 'Asha'}
        if path == 'me/accounts':
            return {'data': state['pages']}
        if path.endswith('/subscribed_apps'):
            state['subscribed'].append((path.split('/')[0], params.get('subscribed_fields'), params.get('access_token')))
            return {'success': True}
        if path in ('p1', 'p2'):
            return {'name': 'Acme Page', 'followers_count': 1200, 'fan_count': 1100}
        if path == 'ig1':
            return {'username': 'acme', 'followers_count': 800, 'follows_count': 40, 'media_count': 12}
        if path.endswith('/posts'):
            return {'data': [{'id': 'p1_9', 'message': 'Launch day', 'created_time': '2026-10-16T08:00:00+0000', 'permalink_url': 'https://fb.test/9',
                              'shares': {'count': 3}, 'reactions': {'summary': {'total_count': 40}}, 'comments': {'summary': {'total_count': 5}}}]}
        if path.endswith('/media'):
            return {'data': [{'id': 'm9', 'caption': 'New feature', 'like_count': 77, 'comments_count': 4, 'permalink': 'https://ig.test/m9', 'media_type': 'IMAGE'}]}
        if path.endswith('/leadgen_forms'):
            return {'data': [{'id': 'f1', 'name': 'Demo form'}]} if path.startswith('p1') else {'data': []}
        if path == 'f1/leads':
            return {'data': [LEAD]}
        if path == '555':
            if state['lead_error']:
                return state['lead_error']
            return LEAD
        if path == '777':
            return {'name': 'Ravi Kumar'}
        if path.endswith('/messages'):
            if state['send_error']:
                return state['send_error']
            return {'message_id': 'm.out1', 'recipient_id': json['recipient']['id']}
        if path.endswith('/comments') or path.endswith('/replies'):
            return {'id': 'reply-1'}
        raise AssertionError(f'unexpected Graph call {path}')

    web.on('GET', GRAPH, answer)
    web.on('POST', GRAPH, answer)
    web.state = state
    return web


LEAD = {'id': '555', 'created_time': '2026-10-17T10:00:00+0000', 'form_id': 'f1', 'ad_name': 'Spring ad', 'campaign_name': 'Spring', 'platform': 'fb',
        'field_data': [{'name': 'full_name', 'values': ['Priya Shah']}, {'name': 'email', 'values': ['priya@shah.test']},
                       {'name': 'phone_number', 'values': ['+919800000000']}, {'name': 'company_name', 'values': ['Shah & Co']}]}


def sign_in(user='owner', provider='meta_page'):
    started = conn_router.oauth_start(conn_router.OAuthStartBody(provider=provider), user_id=user)
    state = unquote(started['url'].split('state=')[1].split('&')[0])
    return conn_router.oauth_meta_callback(code='auth-code', state=state)


def conns(world, provider):
    return [c for c in world.tables.get('connections', []) if c['provider'] == provider]


def push(payload, secret=SECRET, headers=None):
    body = json.dumps(payload).encode()
    sig = {'X-Hub-Signature-256': 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}
    return conn_router.receive_meta(body, headers if headers is not None else sig)


def page_message(text, mid='m1', sender='777', ts=None, page='p1'):
    return {'object': 'page', 'entry': [{'id': page, 'messaging': [{'sender': {'id': sender}, 'recipient': {'id': page}, 'timestamp': ts or now_ms(),
                                                                   'message': {'mid': mid, 'text': text}}]}]}


# ───────────────────────── the switch ─────────────────────────

def test_it_is_off_unless_the_flag_and_every_key_are_set(world, monkeypatch):
    for key in ('META_CHANNELS_ENABLED', 'META_APP_ID', 'META_APP_SECRET', 'META_WEBHOOK_VERIFY_TOKEN'):
        monkeypatch.delenv(key, raising=False)
    listed = {p['provider']: p for p in conn_router.providers(user_id='owner')['providers']}
    for name in meta.META_PROVIDERS:
        assert listed[name]['available'] is False and listed[name]['restricted'] is False and 'approved test accounts' in listed[name]['unavailable_note']
    with pytest.raises(HTTPException) as err:
        conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_page'), user_id='owner')
    assert err.value.status_code == 503
    monkeypatch.setenv('META_CHANNELS_ENABLED', 'true')
    assert meta.enabled() is False                         # the flag alone is not enough: the app id, secret and verify token are needed too


def test_only_listed_organizations_can_use_it_while_meta_has_not_approved_the_app(graph, monkeypatch):
    monkeypatch.setenv('META_ALLOWED_ORGS', 'org-2')
    listed = {p['provider']: p for p in conn_router.providers(user_id='owner')['providers']}
    assert listed['meta_page']['available'] is False and listed['meta_page']['restricted'] is True
    with pytest.raises(HTTPException) as err:
        conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_page'), user_id='owner')
    assert err.value.status_code == 503
    assert {p['provider']: p for p in conn_router.providers(user_id='other')['providers']}['meta_page']['available'] is True
    monkeypatch.setenv('META_ALLOWED_ORGS', 'org-1, org-2')
    assert conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_page'), user_id='owner')['url'].startswith('https://www.facebook.com/')


def test_a_business_login_configuration_replaces_the_scope_list(graph, monkeypatch):
    monkeypatch.setenv('META_LOGIN_CONFIG_ID', 'cfg-123')
    url = conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_page'), user_id='owner')['url']
    assert 'config_id=cfg-123' in url and 'override_default_response_type=true' in url and 'scope=' not in url


def test_the_sign_in_address_asks_for_every_permission_with_a_signed_state_and_never_shows_the_secret(graph):
    url = conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_leads'), user_id='owner')['url']
    assert 'client_id=app-1' in url and SECRET not in url and 'oauth%2Fmeta%2Fcallback' in url
    for scope in ('leads_retrieval', 'instagram_manage_messages', 'pages_messaging'):
        assert scope in unquote(url)
    assert vault.read_state(unquote(url.split('state=')[1].split('&')[0]))['p'] == 'meta_leads'
    for user in ('member', 'other'):
        with pytest.raises(HTTPException):
            conn_router.oauth_start(conn_router.OAuthStartBody(provider='meta_page'), user_id=user)


# ───────────────────────── the sign-in ─────────────────────────

def test_one_sign_in_connects_every_shared_page_its_lead_ads_and_its_instagram_account(world, graph):
    response = sign_in(provider='meta_instagram')
    assert response.status_code == 302 and response.headers['location'].endswith('#/connections?connected=meta_instagram')
    assert len(conns(world, 'meta_page')) == 2 and len(conns(world, 'meta_leads')) == 2 and len(conns(world, 'meta_instagram')) == 1
    ig = conns(world, 'meta_instagram')[0]
    assert ig['external_id'] == 'ig1' and ig['label'] == '@acme' and ig['owner_id'] == 'org-1' and ig['config']['fb_user_id'] == 'fb-user-1'
    assert {c['status'] for c in world.tables['connections']} == {'connected'}
    assert sorted(p for p, _, _ in graph.state['subscribed']) == ['p1', 'p2']                    # once per Page
    assert graph.state['subscribed'][0][1] == meta.SUBSCRIBED_FIELDS and graph.state['subscribed'][0][2] == 'PAGE-TOKEN-1'
    for token in ('PAGE-TOKEN-1', 'long-user', 'short-user'):
        assert token not in str(world.tables['connections']) and token not in str(world.tables['signals'])
        assert all(token not in s['encrypted_secret'] for s in world.tables['connection_secrets'])
    assert 'PAGE-TOKEN-1' in vault.decrypt_secret(world.tables['connection_secrets'][0]['encrypted_secret'])
    assert {s['name'] for s in world.tables['signals']} >= {'page_followers', 'page_likes', 'post_reactions', 'ig_followers', 'ig_post_likes', 'lead'}


def test_signing_in_again_refreshes_the_access_instead_of_duplicating(world, graph):
    sign_in()
    sign_in()
    assert len(world.tables['connections']) == 5


def test_a_required_permission_that_was_turned_off_connects_nothing_and_says_which(world, graph):
    graph.state['perms']['leads_retrieval'] = 'declined'
    response = sign_in()
    assert 'leads_retrieval' in unquote(response.headers['location']) and 'oauth_error' in response.headers['location']
    assert not world.tables.get('connections')
    graph.state['perms']['leads_retrieval'] = 'granted'
    graph.state['perms']['business_management'] = 'declined'                  # the optional one may be refused
    assert sign_in().headers['location'].endswith('connected=meta_page')


def test_no_shared_page_connects_nothing_and_says_so(world, graph):
    graph.state['pages'] = []
    assert 'No+Facebook+Page' in sign_in().headers['location'] or 'No%20Facebook%20Page' in sign_in().headers['location']
    assert not world.tables.get('connections')


def test_refusing_at_facebook_connects_nothing(world, graph):
    response = conn_router.oauth_meta_callback(code='', state='', error='access_denied')
    assert 'oauth_error' in response.headers['location'] and not world.tables.get('connections')


# ───────────────────────── Meta's webhook ─────────────────────────

def test_meta_verifies_the_callback_address_with_the_token(graph):
    assert hooks.meta_verify(mode='subscribe', token='verify-me', challenge='1234').body == b'1234'
    for mode, token in (('subscribe', 'wrong'), ('other', 'verify-me'), ('subscribe', '')):
        with pytest.raises(HTTPException) as err:
            hooks.meta_verify(mode=mode, token=token, challenge='1')
        assert err.value.status_code == 403


def test_what_meta_pushes_must_carry_a_valid_signature(world, graph):
    sign_in()
    for headers in ({}, {'X-Hub-Signature-256': 'sha256=' + '0' * 64}, {'X-Hub-Signature-256': 'nope'}):
        with pytest.raises(HTTPException) as err:
            push(page_message('hi'), headers=headers)
        assert err.value.status_code == 401
    with pytest.raises(HTTPException) as err:
        push(page_message('hi'), secret='someone-elses-secret')
    assert err.value.status_code == 401
    assert not signals_named(world, 'facebook_message')
    assert push(page_message('hi'))['received'] == 1
    with pytest.raises(HTTPException) as err:
        conn_router.receive_meta(b'x' * 1_100_000, {})
    assert err.value.status_code == 413


def test_a_page_message_is_stored_once_with_the_senders_name_and_an_echo_is_ignored(world, graph):
    sign_in()
    assert push(page_message('What is the price for 50 users?'))['received'] == 1
    stored = signals_named(world, 'facebook_message')
    assert len(stored) == 1 and stored[0]['kind'] == 'mention' and stored[0]['text_value'] == 'What is the price for 50 users?'
    assert stored[0]['entity']['from'] == 'Ravi Kumar' and stored[0]['entity']['sender_id'] == '777'
    assert stored[0]['connection_id'] == conns(world, 'meta_page')[0]['id']
    assert push(page_message('What is the price for 50 users?'))['received'] == 0                  # Meta delivered it twice
    echo = page_message('our own reply', mid='m2')
    echo['entry'][0]['messaging'][0]['message']['is_echo'] = True
    own = page_message('from the page itself', mid='m3', sender='p1')
    assert push(echo)['received'] == 0 and push(own)['received'] == 0
    assert len(signals_named(world, 'facebook_message')) == 1


def test_messages_for_one_page_never_reach_another_page_or_another_organization(world, graph):
    sign_in()
    world.tables['connections'].append({'id': 'x', 'owner_id': 'org-2', 'provider': 'meta_page', 'external_id': 'p9', 'status': 'connected', 'config': {}})
    push(page_message('hello', page='p2'))
    assert [s['connection_id'] for s in signals_named(world, 'facebook_message')] == [c['id'] for c in conns(world, 'meta_page') if c['external_id'] == 'p2']
    assert push(page_message('hello', mid='m7', page='unknown-page'))['received'] == 0
    assert push({'object': 'user', 'entry': [{'id': 'p1'}]})['received'] == 0


def test_a_paused_connection_receives_nothing(world, graph):
    sign_in()
    conns(world, 'meta_page')[0]['status'] = 'paused'
    assert push(page_message('hello'))['received'] == 0


def test_a_comment_on_a_post_is_stored_and_the_pages_own_comment_is_not(world, graph):
    sign_in()
    comment = {'object': 'page', 'entry': [{'id': 'p1', 'changes': [{'field': 'feed', 'value': {
        'item': 'comment', 'verb': 'add', 'comment_id': 'c1', 'post_id': 'p1_9', 'message': 'Do you deliver to Pune?', 'created_time': 1792000000,
        'from': {'id': '888', 'name': 'Meera'}}}]}]}
    assert push(comment)['received'] == 1
    got = signals_named(world, 'facebook_comment')[0]
    assert got['text_value'] == 'Do you deliver to Pune?' and got['entity']['author'] == 'Meera' and got['entity']['comment_id'] == 'c1'
    own = json.loads(json.dumps(comment))
    own['entry'][0]['changes'][0]['value'].update(comment_id='c2', **{'from': {'id': 'p1', 'name': 'Acme Page'}})
    edited = json.loads(json.dumps(comment))
    edited['entry'][0]['changes'][0]['value'].update(comment_id='c3', verb='edited')
    assert push(own)['received'] == 0 and push(edited)['received'] == 0


def test_instagram_messages_and_comments_go_to_the_instagram_connection_only(world, graph):
    sign_in()
    dm = {'object': 'instagram', 'entry': [{'id': 'ig1', 'messaging': [{'sender': {'id': '777'}, 'recipient': {'id': 'ig1'}, 'timestamp': now_ms(),
                                                                     'message': {'mid': 'igm1', 'text': 'Hi, do you have a demo?'}}]}]}
    comment = {'object': 'instagram', 'entry': [{'id': 'ig1', 'changes': [{'field': 'comments', 'value': {
        'id': 'ic1', 'text': 'How much is it?', 'from': {'id': '999', 'username': 'neha_k'}, 'media': {'id': 'm9'}}}]}]}
    assert push(dm)['received'] == 1 and push(comment)['received'] == 1
    ig = conns(world, 'meta_instagram')[0]['id']
    assert [s['connection_id'] for s in signals_named(world, 'instagram_message') + signals_named(world, 'instagram_comment')] == [ig, ig]
    assert signals_named(world, 'instagram_comment')[0]['entity']['author'] == 'neha_k'
    assert not signals_named(world, 'facebook_message')


def test_a_new_lead_is_fetched_stored_once_and_not_duplicated_by_the_next_sync(world, graph):
    sign_in()
    hook = {'object': 'page', 'entry': [{'id': 'p1', 'changes': [{'field': 'leadgen', 'value': {'leadgen_id': '555', 'form_id': 'f1', 'page_id': 'p1'}}]}]}
    before = len(signals_named(world, 'lead'))
    assert before == 1                                                    # the sign-in already read the form's waiting leads
    assert push(hook)['received'] == 0                                    # the same lead, already stored
    world.tables['signals'] = [s for s in world.tables['signals'] if s['name'] != 'lead']
    assert push(hook)['received'] == 1
    lead = signals_named(world, 'lead')[0]
    assert lead['kind'] == 'lead' and lead['entity']['email'] == 'priya@shah.test' and lead['entity']['phone'] == '+919800000000'
    assert lead['entity']['name'] == 'Priya Shah' and lead['entity']['company'] == 'Shah & Co' and lead['entity']['campaign_name'] == 'Spring'
    assert lead['connection_id'] == conns(world, 'meta_leads')[0]['id'] and lead['dedupe_key'] == 'lead:555'
    leads_conn = conns(world, 'meta_leads')[0]
    leads_conn['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn_router.sync_now(leads_conn['id'], user_id='owner')
    assert len(signals_named(world, 'lead')) == 1


def test_a_lead_that_cannot_be_read_yet_asks_meta_to_try_again_but_a_dead_token_does_not(world, graph):
    sign_in()
    world.tables['signals'] = [s for s in world.tables['signals'] if s['name'] != 'lead']
    hook = {'object': 'page', 'entry': [{'id': 'p1', 'changes': [{'field': 'leadgen', 'value': {'leadgen_id': '555', 'form_id': 'f1'}}]}]}
    graph.state['lead_error'] = FakeResponse(400, {'error': {'code': 4, 'message': 'too many calls'}})
    with pytest.raises(HTTPException) as err:
        push(hook)
    assert err.value.status_code == 503 and not signals_named(world, 'lead')
    graph.state['lead_error'] = FakeResponse(400, {'error': {'code': 190, 'message': 'expired'}})
    assert push(hook)['received'] == 0
    leads_conn = conns(world, 'meta_leads')[0]
    assert leads_conn['status'] == 'error' and 'Connect with Facebook again' in leads_conn['last_error']


# ───────────────────────── replying ─────────────────────────

def reply(world, connection, **params):
    return conn_router.run_action(connection['id'], 'send_message', conn_router.ActionBody(params=params), user_id='owner')


def test_a_reply_inside_24_hours_is_sent_as_a_response_and_recorded(world, graph):
    sign_in()
    push(page_message('Hello, is this available?'))
    page = conns(world, 'meta_page')[0]
    out = reply(world, page, recipient_id='777', text='  Yes, it is.  ')
    assert out['ok'] and out['message_id'] == 'm.out1'
    sent = graph.posts(GRAPH + 'p1/messages')[0]
    assert sent['json'] == {'recipient': {'id': '777'}, 'messaging_type': 'RESPONSE', 'message': {'text': 'Yes, it is.'}} and sent['params']['access_token'] == 'PAGE-TOKEN-1'
    assert signals_named(world, 'facebook_reply_sent')[0]['entity']['recipient_id'] == '777'


def test_a_reply_after_24_hours_or_to_a_stranger_or_by_a_member_is_refused(world, graph):
    sign_in()
    push(page_message('Old message', mid='old', ts=now_ms(30)))
    page = conns(world, 'meta_page')[0]
    for params in ({'recipient_id': '777', 'text': 'too late'}, {'recipient_id': '123', 'text': 'who?'}):
        with pytest.raises(HTTPException) as err:
            reply(world, page, **params)
        assert err.value.status_code == 422 and '24 hours' in err.value.detail
    push(page_message('Fresh', mid='new'))
    for params in ({'recipient_id': '777', 'text': ''}, {'recipient_id': '', 'text': 'x'}, {'recipient_id': '777', 'text': 'x' * 1001}):
        with pytest.raises(HTTPException):
            reply(world, page, **params)
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(page['id'], 'send_message', conn_router.ActionBody(params={'recipient_id': '777', 'text': 'hi'}), user_id='member')
    assert err.value.status_code == 403
    assert not graph.posts(GRAPH + 'p1/messages')


def test_the_daily_reply_limit_stops_a_runaway_sender(world, graph, monkeypatch):
    sign_in()
    push(page_message('Hello'))
    monkeypatch.setattr(meta, 'DAILY_REPLY_CAP', 2)
    page = conns(world, 'meta_page')[0]
    for i in range(2):
        reply(world, page, recipient_id='777', text=f'reply {i}')
        world.tables['signals'][-1]['dedupe_key'] = f'k{i}'
    with pytest.raises(HTTPException) as err:
        reply(world, page, recipient_id='777', text='one too many')
    assert err.value.status_code == 422 and 'limit' in err.value.detail


def test_facebooks_error_codes_are_turned_into_plain_words(world, graph):
    sign_in()
    push(page_message('Hello'))
    page = conns(world, 'meta_page')[0]
    cases = [({'code': 190}, 'Connect with Facebook again'), ({'code': 10, 'error_subcode': 2018278}, '24 hours'), ({'code': 200}, 'permission'),
             ({'code': 4}, 'limit'), ({'code': 100, 'message': 'Invalid parameter'}, 'Invalid parameter')]
    for error, words in cases:
        graph.state['send_error'] = FakeResponse(400, {'error': error})
        with pytest.raises(HTTPException) as err:
            reply(world, page, recipient_id='777', text='hi')
        assert err.value.status_code == 422 and words in err.value.detail


def test_a_comment_reply_goes_to_the_right_endpoint_on_each_network(world, graph):
    sign_in()
    page, ig = conns(world, 'meta_page')[0], conns(world, 'meta_instagram')[0]
    conn_router.run_action(page['id'], 'reply_comment', conn_router.ActionBody(params={'comment_id': 'c1', 'text': 'Yes we do'}), user_id='owner')
    conn_router.run_action(ig['id'], 'reply_comment', conn_router.ActionBody(params={'comment_id': 'ic1', 'text': 'See our bio'}), user_id='owner')
    assert graph.posts(GRAPH + 'c1/comments')[0]['json'] == {'message': 'Yes we do'}
    assert graph.posts(GRAPH + 'ic1/replies')[0]['json'] == {'message': 'See our bio'}
    with pytest.raises(HTTPException):
        conn_router.run_action(page['id'], 'reply_comment', conn_router.ActionBody(params={'comment_id': '', 'text': 'x'}), user_id='owner')


# ───────────────────────── alerts ─────────────────────────

def test_leads_and_buying_messages_become_alerts_and_plain_chat_does_not():
    lead = {'name': 'lead', 'text_value': 'Priya', 'entity': {'name': 'Priya Shah', 'email': 'p@s.test', 'campaign_name': 'Spring'}}
    price = {'name': 'facebook_message', 'text_value': 'What is the price?', 'entity': {'from': 'Ravi'}}
    chat = {'name': 'instagram_message', 'text_value': 'thanks!', 'entity': {'from': 'Neha'}}
    nice = {'name': 'facebook_comment', 'text_value': 'Great post', 'entity': {'author': 'Meera'}}
    ask = {'name': 'instagram_comment', 'text_value': 'how much is the demo?', 'entity': {'author': 'neha_k'}}
    out = alerts.derive_alerts('meta_leads', [lead, price, chat, nice, ask])
    assert [a.events for a in out] == [('new_lead',), ('buying_comment', 'new_message'), ('new_message',), ('buying_comment',)]
    assert 'Priya Shah' in out[0].text and 'Spring' in out[0].text and 'Facebook message from Ravi' in out[1].text and 'Instagram comment from neha_k' in out[3].text
    assert 'new_lead' in alerts.clean_events(['new_lead', 'bogus'])


def test_a_new_lead_reaches_slack_the_moment_it_arrives(world, graph):
    from tests.test_connections_channels import connect
    graph.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(200, {}))
    connect('slack', {'webhook_url': 'https://hooks.slack.com/services/T/B/x'})
    sign_in()
    world.tables['signals'] = [s for s in world.tables['signals'] if s['name'] != 'lead']
    graph.calls.clear()
    push({'object': 'page', 'entry': [{'id': 'p1', 'changes': [{'field': 'leadgen', 'value': {'leadgen_id': '555', 'form_id': 'f1'}}]}]})
    sent = graph.posts('https://hooks.slack.com/')
    assert len(sent) == 1 and 'New lead: Priya Shah' in sent[0]['json']['text']


# ───────────────────────── Meta's data-deletion callbacks ─────────────────────────

def signed_request(payload, secret=SECRET):
    enc = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip('=')
    body = enc(json.dumps(payload).encode())
    return enc(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()) + '.' + body


def test_a_data_deletion_request_removes_that_persons_connections_and_nobody_elses(world, graph):
    sign_in()
    world.tables['connections'].append({'id': 'keep', 'owner_id': 'org-2', 'provider': 'meta_page', 'external_id': 'p7', 'status': 'connected', 'config': {'fb_user_id': 'someone-else'}})
    push(page_message('hello'))
    out = hooks.meta_data_deletion(signed_request=signed_request({'algorithm': 'HMAC-SHA256', 'user_id': 'fb-user-1'}))
    assert out['removed'] == 5 and out['confirmation_code'] in out['url'] and out['url'].startswith('https://api.example.test/api/raptor/hooks/meta/deletion-status')
    assert [c['id'] for c in world.tables['connections']] == ['keep']
    assert not world.tables['connection_secrets'] and not world.tables['signals']
    assert 'deleted' in hooks.meta_deletion_status(code='abc-123').body.decode()


def test_deauthorizing_removes_the_connections_too_and_a_forged_request_does_nothing(world, graph):
    sign_in()
    for forged in (signed_request({'algorithm': 'HMAC-SHA256', 'user_id': 'fb-user-1'}, secret='wrong'), 'garbage', '', 'a.b',
                   signed_request({'algorithm': 'none', 'user_id': 'fb-user-1'})):
        with pytest.raises(HTTPException) as err:
            hooks.meta_deauthorize(signed_request=forged)
        assert err.value.status_code == 401
    assert len(world.tables['connections']) == 5
    hooks.meta_deauthorize(signed_request=signed_request({'algorithm': 'HMAC-SHA256', 'user_id': 'fb-user-1'}))
    assert not world.tables['connections']


def test_the_deletion_status_page_shows_only_a_safe_code(graph):
    html = hooks.meta_deletion_status(code='<script>alert(1)</script>').body.decode()
    assert '<script>' not in html and 'scriptalert1script' in html


def test_parse_signed_request_rejects_a_bad_signature_and_a_wrong_algorithm(graph):
    assert meta.parse_signed_request(signed_request({'algorithm': 'HMAC-SHA256', 'user_id': '1'}))['user_id'] == '1'
    with pytest.raises(ConnectorError):
        meta.parse_signed_request(signed_request({'algorithm': 'HMAC-SHA256', 'user_id': '1'}, secret='nope'))
